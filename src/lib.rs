#![cfg_attr(docsrs, feature(doc_cfg))]
//! HTTP clients that capture the request and response messages of each exchange.
//!
//! A [`Client`] performs one HTTP exchange and returns its stored HTTP/1 representation in a
//! [`CapturedExchange`]. No client follows redirects, decodes content, keeps cookies, retries, or
//! reuses a connection, so one fetch is exactly one request and one response.
//!
//! Three clients are provided:
//!
//! - [`Recorder`](recorder::Recorder) performs HTTP/1.1 over its own connection and stores the
//!   exact bytes sent and received.
//! - [`ReqwestClient`](reqwest::ReqwestClient) performs HTTP/1.1 with `reqwest` and reconstructs
//!   both messages from the parts `reqwest` exposes.
//! - `WreqClient` (in the `wreq` module, behind the `wreq` feature) uses `BoringSSL` with browser
//!   emulation. It stores HTTP/1 bytes exactly and reconstructs HTTP/2 exchanges, which it
//!   negotiates only when asked to.
//!
//! [`CapturedExchange::fidelity`] says whether a stored exchange is exact or reconstructed, and
//! [`CapturedExchange::http_protocol`] says which HTTP version it used. Every client frames and
//! truncates responses with [`ResponseCapture`](framing::ResponseCapture), so a size limit, a
//! disconnect, or a timeout after the header section returns a truncated response with the same
//! bytes whichever client performed the exchange.
//!
//! [`message`] parses stored messages, [`body`] removes transfer coding from them, and
//! [`reconstruct`] rebuilds HTTP/1.1 messages for clients that only see parsed parts.

pub mod body;
mod chunked;
mod failure;
pub mod framing;
pub mod message;
mod parsing;
mod read;
pub mod reconstruct;
pub mod recorder;
mod request;
pub mod reqwest;
mod runtime;
mod socks;
mod tls;
#[cfg(feature = "wreq")]
#[cfg_attr(docsrs, doc(cfg(feature = "wreq")))]
pub mod wreq;

use std::borrow::Cow;
use std::fmt::Debug;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fluent_uri::Uri;
use http::{HeaderMap, Method, Uri as HttpUri};

use crate::framing::{ResponseError, Truncation};
use crate::message::ResponseMetadata;

/// The connection and I/O timeout a client starts from.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The response-size bound a client starts from, in bytes.
pub const DEFAULT_MAX_RESPONSE_LENGTH: u64 = 256 * 1024 * 1024;

/// Errors returned by a client while performing a captured exchange.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A client failed in a way that has no variant of its own.
    ///
    /// The [`Recorder`](recorder::Recorder) never produces this variant.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The target is not an absolute HTTP or HTTPS URI.
    #[error("the target URI must be absolute, with an `http` or `https` scheme")]
    UnsupportedScheme,
    /// The target names no host.
    #[error("the target URI names no host")]
    MissingHost,
    /// The target is not a URI as RFC 3986 defines one.
    #[error("the target URI is not a URI: {0}")]
    TargetUri(#[from] fluent_uri::ParseError),
    /// The host cannot name a TLS server.
    #[error("the host cannot name a TLS server: {0}")]
    ServerName(#[from] rustls::pki_types::InvalidDnsNameError),
    /// The TLS session could not be created.
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    /// An I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Response framing is malformed.
    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// A proxy URI that the clients cannot use, with the reason.
///
/// Every client accepts the same proxies: `socks5://` and `socks5h://` URIs with a host, an
/// optional port, and optional username and password credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid proxy: {0}")]
pub struct InvalidProxy(pub &'static str);

/// Whether the stored messages of an exchange are the bytes that crossed the connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Fidelity {
    /// The stored messages are the exact HTTP/1 bytes sent and received.
    Exact,
    /// Both messages were rebuilt from parsed parts.
    ///
    /// Header names are lowercased, the reason phrase is the canonical one, and chunk boundaries
    /// are those the HTTP library delivered rather than those the origin sent.
    Reconstructed,
}

/// The HTTP version an exchange used on its connection, whatever form its messages are stored in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpProtocol {
    /// HTTP/1.0 or HTTP/1.1.
    Http1,
    /// HTTP/2.
    Http2,
}

/// A negotiated TLS protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TlsVersion {
    /// TLS 1.0.
    V1_0,
    /// TLS 1.1.
    V1_1,
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
}

/// One captured exchange: its stored messages and the facts recorded about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedExchange {
    /// Stored request message, exact or reconstructed as `fidelity` says.
    pub request: Vec<u8>,
    /// Stored response message, from the final status line through the recorded end.
    pub response: Vec<u8>,
    /// Whether the stored messages are the bytes that crossed the connection.
    pub fidelity: Fidelity,
    /// The HTTP version the exchange used. The stored messages are HTTP/1 messages either way.
    pub http_protocol: HttpProtocol,
    /// The negotiated TLS version, when the exchange used TLS and the client can observe it.
    pub tls_version: Option<TlsVersion>,
    /// Parsed fields and boundaries of the stored response.
    pub response_metadata: ResponseMetadata,
    /// The requested URI.
    pub target_uri: Uri<String>,
    /// The origin IP address, when known. Proxied captures omit it because the socket peer is
    /// the proxy and the tunnel does not reliably identify the origin address.
    pub ip_address: Option<IpAddr>,
    /// When network activity began.
    pub date: DateTime<Utc>,
    /// Time from starting network activity to finishing the response.
    pub fetch_time: Duration,
    /// Why the response was truncated, if applicable.
    pub truncated: Option<Truncation>,
}

impl CapturedExchange {
    /// Return the response entity-body with transfer coding removed and content coding preserved.
    ///
    /// The response to a `HEAD` request, and a `204` or `304` response, has no body, so its
    /// entity-body is empty whatever its header section declares. A chunked response that was
    /// truncated has an incomplete chunked body, for which this fails;
    /// [`stored_body`](Self::stored_body) returns what arrived.
    pub fn entity_body(&self) -> Result<Cow<'_, [u8]>, body::Error> {
        if self.request.starts_with(b"HEAD ") || matches!(self.response_metadata.status, 204 | 304)
        {
            Ok(Cow::Borrowed(&[]))
        } else {
            body::entity_body(&self.response)
        }
    }

    /// Return the stored bytes after the response header section without transfer decoding.
    #[must_use]
    pub fn stored_body(&self) -> &[u8] {
        &self.response[self.response_metadata.body_offset..]
    }
}

/// The request of one exchange.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The request method.
    pub method: &'a Method,
    /// The absolute `http` or `https` URI to request.
    pub target: &'a HttpUri,
    /// The request headers.
    pub headers: &'a HeaderMap,
    /// The request body, if there is one.
    pub body: Option<&'a [u8]>,
}

/// Performs and captures one HTTP exchange.
///
/// Implementations are shared across threads, so they must be `Send`, `Sync`, and cheap to clone
/// behind an `Arc`.
pub trait Client: Debug + Send + Sync + 'static {
    /// Perform one exchange, finishing before `deadline` when one is given.
    ///
    /// A deadline that passes before a response header section arrives is an error; one that
    /// passes afterwards truncates the response with [`Truncation::Time`]. Report failures that
    /// have no [`Error`] variant of their own as [`Error::Other`].
    ///
    /// # Errors
    ///
    /// Fails when the target is unusable, the transport fails before a usable response header
    /// section, or the response cannot be framed.
    fn fetch_within(
        &self,
        request: Request<'_>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error>;

    /// Perform one exchange without a deadline.
    ///
    /// # Errors
    ///
    /// As for [`fetch_within`](Self::fetch_within).
    fn fetch(&self, request: Request<'_>) -> Result<CapturedExchange, Error> {
        self.fetch_within(request, None)
    }

    /// Perform one exchange, finishing before `deadline`.
    ///
    /// # Errors
    ///
    /// As for [`fetch_within`](Self::fetch_within), including when `deadline` has already passed.
    fn fetch_by(&self, request: Request<'_>, deadline: Instant) -> Result<CapturedExchange, Error> {
        self.fetch_within(request, Some(deadline))
    }
}
