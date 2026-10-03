//! HTTP/1 wire capture and reconstructed HTTP/2 capture with browser TLS emulation.
//!
//! Each fetch owns an isolated client and runtime. Redirects, retries, cookies, automatic proxies,
//! decompression, and pooling are disabled. The selected profile supplies TLS and HTTP/2 settings;
//! configured request headers override profile headers.
//!
//! HTTP/1 messages are captured exactly, with [`Fidelity::Exact`](crate::Fidelity::Exact). HTTP/2
//! is used only by a backend that enables it with [`WreqBackend::http2`]. An HTTP/2 exchange is
//! reconstructed as HTTP/1.1 messages, with
//! [`Fidelity::ReconstructedHttp2`](crate::Fidelity::ReconstructedHttp2) identifying its original
//! protocol. Content coding is preserved and chunked framing retains response trailers. Both HTTP
//! versions also record the negotiated TLS version when available.
//!
//! Calls are synchronous and can run inside an existing Tokio runtime. See the crate README for
//! capture limits, reconstruction, and timeout semantics.

mod capture;

use std::time::{Duration, Instant};

use http::{HeaderMap, Method, Uri};
use serde::de::Deserialize;
use serde::de::value::StrDeserializer;
use wreq_util::Profile;

use crate::{
    Backend, CapturedExchange, DEFAULT_MAX_RESPONSE_LENGTH, DEFAULT_TIMEOUT, Error, InvalidProxy,
    runtime, socks,
};

/// An isolated HTTP/1 and HTTP/2 backend using `BoringSSL` and browser emulation.
#[derive(Clone)]
pub struct WreqBackend {
    profile: Profile,
    http2: bool,
    proxy: Option<wreq::Proxy>,
    connect_timeout: Option<Duration>,
    io_timeout: Option<Duration>,
    max_response_length: Option<u64>,
    cert_store: Option<wreq::tls::trust::CertStore>,
}

impl std::fmt::Debug for WreqBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WreqBackend")
            .field("profile", &self.profile)
            .field("http2", &self.http2)
            .field("proxied", &self.proxy.is_some())
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("max_response_length", &self.max_response_length)
            .field("custom_cert_store", &self.cert_store.is_some())
            .finish()
    }
}

impl WreqBackend {
    /// Select a profile, including its TLS and HTTP/2 settings.
    ///
    /// The backend starts with HTTP/2 disabled, [`DEFAULT_TIMEOUT`] for connecting and for idle
    /// progress, and [`DEFAULT_MAX_RESPONSE_LENGTH`] for the response.
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self {
            profile,
            http2: false,
            proxy: None,
            connect_timeout: Some(DEFAULT_TIMEOUT),
            io_timeout: Some(DEFAULT_TIMEOUT),
            max_response_length: Some(DEFAULT_MAX_RESPONSE_LENGTH),
            cert_store: None,
        }
    }

    /// Replace the profile used for every request.
    #[must_use]
    pub const fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    /// Allow HTTP/2, which is off unless this is called with `true`.
    ///
    /// When enabled, the backend offers the profile's ALPN protocols and uses HTTP/2 when the
    /// origin selects it. When disabled, it offers only `http/1.1`. A browser profile normally
    /// offers `h2` as well, so the `ClientHello` of a backend without HTTP/2 differs from the
    /// emulated browser's in its ALPN extension.
    #[must_use]
    pub const fn http2(mut self, enabled: bool) -> Self {
        self.http2 = enabled;
        self
    }

    /// Set an explicit proxy for every request, or use direct connections with `None`.
    ///
    /// Supports `socks5://` for local DNS and `socks5h://` for proxy DNS, with optional username
    /// and password credentials. Environment proxy settings remain disabled. This backend accepts
    /// exactly the proxies the [`Recorder`](crate::recorder::Recorder) accepts.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProxy`] for a malformed or unsupported URI.
    pub fn proxy(mut self, proxy: Option<&str>) -> Result<Self, InvalidProxy> {
        self.proxy = proxy
            .map(|proxy| {
                socks::Proxy::parse(proxy)?;
                wreq::Proxy::all(proxy).map_err(|_| InvalidProxy("rejected by wreq"))
            })
            .transpose()?;
        Ok(self)
    }

    /// Bound connecting, including DNS and TLS, or remove the bound with `None`.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Bound idle exchange progress after connecting, or remove the bound with `None`.
    ///
    /// HTTP/2 connection control traffic does not count as response progress.
    #[must_use]
    pub const fn io_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Bound stored response bytes, including the final head and transfer framing.
    ///
    /// HTTP/2 counts the reconstructed message, not binary connection traffic.
    #[must_use]
    pub const fn max_response_length(mut self, limit: Option<u64>) -> Self {
        self.max_response_length = limit;
        self
    }

    /// Replace the default Mozilla root certificate store.
    #[must_use]
    pub fn tls_cert_store(mut self, store: wreq::tls::trust::CertStore) -> Self {
        self.cert_store = Some(store);
        self
    }
}

/// A profile name that no known browser/client profile matches.
#[derive(Clone, Debug, thiserror::Error)]
#[error("unknown profile `{0}`")]
pub struct UnknownProfile(pub String);

/// Look up a profile by the name used in configuration, such as `chrome_136`.
///
/// # Errors
///
/// Fails when no profile has that name.
pub fn parse_profile(name: &str) -> Result<Profile, UnknownProfile> {
    Profile::deserialize(StrDeserializer::<serde::de::value::Error>::new(name))
        .map_err(|_| UnknownProfile(name.to_owned()))
}

/// Report a wreq failure through the catch-all backend error variant.
fn backend_error(error: wreq::Error) -> Error {
    Error::Other(Box::new(error))
}

impl Backend for WreqBackend {
    /// Perform and retain exactly one application exchange.
    ///
    /// A deadline covers DNS, connecting, and response capture.
    fn fetch_within(
        &self,
        method: &Method,
        target: &Uri,
        headers: &HeaderMap,
        body: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        runtime::fetch(target, deadline, || {
            self.capture(method, target, headers, body, deadline)
        })
    }
}
