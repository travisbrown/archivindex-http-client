//! A capture client built on `reqwest`.
//!
//! [`ReqwestClient`] performs an HTTP/1.1 exchange with `reqwest` and stores both messages rebuilt
//! from the parts `reqwest` exposes, so its exchanges have [`Fidelity::Reconstructed`]. Use
//! the [`Recorder`](crate::recorder::Recorder) when the stored bytes must be the ones that crossed
//! the connection.
//!
//! The stored request is built from the parts given to `reqwest`, which the client completes first
//! so that `reqwest` has nothing to add. The tests compare it with the bytes an origin receives,
//! but the client does not observe the connection, so the stored request is what `reqwest` is
//! expected to send and not a record of what it sent.
//!
//! The stored response differs from the origin's bytes in these ways:
//!
//! - Field names are lowercased, and the whitespace around field values is normalized.
//! - The reason phrase is the canonical one for the status code.
//! - Interim `1xx` responses are dropped.
//! - A chunked body is stored chunked, with one chunk for each piece of body data `reqwest`
//!   delivers. Chunk boundaries are therefore not the origin's, and chunk extensions are lost.
//!
//! Content coding is never removed, so the entity-body is the one the origin sent. The client
//! turns off each of `reqwest`'s decoders, so this holds even when another crate in the build
//! enables them.
//!
//! The negotiated TLS version is reported for direct connections only, because `reqwest` does not
//! expose it for a connection made through a SOCKS proxy.

mod request;

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use fluent_uri::Uri;
use http::{HeaderMap, Method};
use http_body_util::BodyExt as _;
use reqwest::tls::TlsInfo;

use crate::framing::{ResponseCapture, ResponseError, Truncation};
use crate::message::ResponseMetadata;
use crate::reconstruct::reconstruct_response;
use crate::{
    CapturedExchange, Client, DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT, Error, Fidelity,
    HttpProtocol, InvalidProxy, Request, TlsVersion, chunked, failure, runtime, socks, tls,
};

/// Performs HTTP/1.1 exchanges with `reqwest` and reconstructs their messages.
///
/// Each fetch uses a new connection. Redirects, retries, decompression, and environment proxy
/// settings are disabled, and there is no cookie store. The client is synchronous and may be
/// called from inside a Tokio runtime.
#[derive(Clone, Debug)]
pub struct ReqwestClient {
    tls: Arc<rustls::ClientConfig>,
    proxy: Option<reqwest::Proxy>,
    connect_timeout: Option<Duration>,
    io_timeout: Option<Duration>,
    max_response_length: Option<u64>,
}

impl ReqwestClient {
    /// Create a client using `webpki-roots` and `aws-lc-rs`, with [`DEFAULT_TIMEOUT`] for
    /// connecting and for each wait, and [`DEFAULT_MAX_RESPONSE_LENGTH`] for the response.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tls: tls::default_config(),
            proxy: None,
            connect_timeout: Some(DEFAULT_TIMEOUT),
            io_timeout: Some(DEFAULT_TIMEOUT),
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
        }
    }

    /// Set a SOCKS5 proxy, or disable proxying with `None`.
    ///
    /// Use `socks5://` to resolve the target locally or `socks5h://` to have the proxy resolve it.
    /// Both accept optional username and password credentials. Environment proxy settings are
    /// ignored. Invalid or unsupported URIs return [`InvalidProxy`].
    pub fn proxy(mut self, proxy: Option<&str>) -> Result<Self, InvalidProxy> {
        self.proxy = proxy
            .map(|proxy| {
                socks::Proxy::parse(proxy)?;
                reqwest::Proxy::all(proxy).map_err(|_| InvalidProxy("rejected by reqwest"))
            })
            .transpose()?;

        Ok(self)
    }

    /// Replace the TLS client configuration, for example to trust a private certificate authority.
    ///
    /// The client offers only `http/1.1` in ALPN, whatever `config` offers.
    #[must_use]
    pub fn tls_config(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls = tls::http1(config);

        self
    }

    /// Set the timeout for connecting, including DNS and TLS, or disable it with `None`.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;

        self
    }

    /// Set the timeout for each wait on the response, or disable it with `None`.
    ///
    /// One wait covers sending the request and receiving the response header section, connecting
    /// included. Every later wait is for the next piece of the body.
    #[must_use]
    pub const fn io_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.io_timeout = timeout;

        self
    }

    /// Set the maximum stored response length, including the header section, or lift it with
    /// `None`.
    ///
    /// The limit counts the reconstructed header section and transfer framing. A response that
    /// ends exactly at the limit is complete. A header section larger than the limit is an error
    /// because it cannot be partially stored.
    #[must_use]
    pub const fn max_response_length(mut self, length: Option<u64>) -> Self {
        self.max_response_length = length;

        self
    }

    /// Build the `reqwest` client for one exchange.
    fn client(&self) -> Result<reqwest::Client, Error> {
        let builder = reqwest::Client::builder()
            .tls_backend_preconfigured((*self.tls).clone())
            .tls_info(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            // Any crate in the build can enable these decoders, and each is on once enabled.
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .pool_max_idle_per_host(0);
        let builder = match &self.proxy {
            Some(proxy) => builder.proxy(proxy.clone()),
            None => builder.no_proxy(),
        };

        let builder = match self.connect_timeout {
            Some(timeout) => builder.connect_timeout(timeout),
            None => builder,
        };

        builder.build().map_err(transport_error)
    }

    /// Wait for `future` until the earlier of the I/O timeout and the deadline.
    ///
    /// Returns `None` when that moment passes first.
    async fn wait<T>(
        &self,
        deadline: Option<Instant>,
        future: impl Future<Output = T>,
    ) -> Option<T> {
        let end = self
            .io_timeout
            .map(|timeout| Instant::now() + timeout)
            .into_iter()
            .chain(deadline)
            .min();

        match end {
            Some(end) => tokio::time::timeout_at(end.into(), future).await.ok(),
            None => Some(future.await),
        }
    }

    async fn capture(
        &self,
        request: Request<'_>,
        target_uri: Uri<String>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        let (prepared, stored_request) = request::prepare(request)?;
        let client = self.client()?;
        let date = Utc::now();
        let clock = Instant::now();

        let response = self
            .wait(deadline, client.execute(prepared))
            .await
            .ok_or_else(failure::timed_out)?
            .map_err(transport_error)?;

        let ip_address = response
            .remote_addr()
            .filter(|_| self.proxy.is_none())
            .map(|address| address.ip());
        let tls_version = response
            .extensions()
            .get::<TlsInfo>()
            .and_then(TlsInfo::version)
            .and_then(tls_version);
        let (head, mut body) = http::Response::from(response).into_parts();
        let chunked = chunked::is_declared(&head.headers);

        let mut capture =
            ResponseCapture::new(*request.method == Method::HEAD, self.max_response_length);
        capture.push(
            &reconstruct_response(head.version, head.status, &head.headers, None).map_err(other)?,
        )?;

        let mut trailers = HeaderMap::new();
        while !capture.is_done() {
            match self.wait(deadline, body.frame()).await {
                None => capture.end(Some(Truncation::Time))?,
                Some(None) if chunked => capture.push(&chunked::last_chunk(&trailers))?,
                Some(None) => capture.end(None)?,
                Some(Some(Err(error))) if failure::is_disconnect(&error) => {
                    capture.end(Some(Truncation::Disconnect))?;
                }
                Some(Some(Err(error))) => return Err(transport_error(error)),
                Some(Some(Ok(frame))) => match frame.into_data() {
                    Ok(piece) if piece.is_empty() => {}
                    Ok(piece) if chunked => {
                        capture.push(chunked::size_line(piece.len()).as_bytes())?;
                        capture.push(&piece)?;
                        capture.push(b"\r\n")?;
                    }
                    Ok(piece) => capture.push(&piece)?,
                    Err(frame) => trailers = frame.into_trailers().unwrap_or_default(),
                },
            }
        }

        let (response, truncated) = capture.into_parts();
        let response_metadata =
            ResponseMetadata::parse(&response).ok_or(ResponseError::MalformedStatusLine)?;
        let fetch_time = clock.elapsed();

        Ok(CapturedExchange {
            request: stored_request,
            response,
            fidelity: Fidelity::Reconstructed,
            http_protocol: HttpProtocol::Http1,
            tls_version,
            response_metadata,
            target_uri,
            ip_address,
            date,
            fetch_time,
            truncated,
        })
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Client for ReqwestClient {
    /// Perform one HTTP/1.1 exchange and reconstruct its messages.
    ///
    /// Missing `host` and `connection` headers are added, as is the `accept: */*` that `reqwest`
    /// sends when the caller supplies no `accept`. The caller's `transfer-encoding` and
    /// `content-length` headers are removed, and a provided body is framed with `content-length`.
    ///
    /// The deadline bounds every wait, so it is a wall-clock limit on the exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for an invalid target, a connection or TLS failure, an incomplete header
    /// section, or malformed response framing. A passed deadline is reported as a timed-out I/O
    /// operation, and other transport failures as [`Error::Io`] when an I/O error caused them. A
    /// size limit, disconnect, or timeout after the header section instead returns a response with
    /// [`CapturedExchange::truncated`] set.
    fn fetch_within(
        &self,
        request: Request<'_>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        runtime::fetch(request.target, deadline, |target_uri| {
            self.capture(request, target_uri, deadline)
        })
    }
}

const fn tls_version(version: reqwest::tls::Version) -> Option<TlsVersion> {
    match version {
        reqwest::tls::Version::TLS_1_0 => Some(TlsVersion::V1_0),
        reqwest::tls::Version::TLS_1_1 => Some(TlsVersion::V1_1),
        reqwest::tls::Version::TLS_1_2 => Some(TlsVersion::V1_2),
        reqwest::tls::Version::TLS_1_3 => Some(TlsVersion::V1_3),
        _ => None,
    }
}

/// Report a `reqwest` failure as an I/O error of the kind that caused it, when one did.
fn transport_error(error: reqwest::Error) -> Error {
    let timed_out = error.is_timeout();

    failure::error(error, timed_out)
}

fn other(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(Box::new(error))
}
