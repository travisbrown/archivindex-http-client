//! Captured HTTP sessions that answer interstitial challenges.
//!
//! [`Session`] wraps an HTTP client, answers Sucuri, Varnish, and Simply.com challenges, and keeps
//! clearance cookies for later requests. Every exchange is returned in request order, including
//! challenge pages and proof verification responses. Failures retain earlier exchanges in
//! [`Error::exchanges`]. Redirect following is opt-in; sessions never execute JavaScript.
//!
//! [`recognize`] and [`ProofOfWork`] also support callers that manage their own request loop.
//!
//! ```no_run
//! use archivindex_http_client::recorder::Recorder;
//! use archivindex_http_client::Request;
//! use archivindex_http_client_challenge::Session;
//! use http::{HeaderMap, Method};
//!
//! let session = Session::new(Recorder::new());
//! let exchanges = session.fetch(Request {
//!     method: &Method::GET,
//!     target: &"https://example.com/".parse()?,
//!     headers: &HeaderMap::new(),
//!     body: None,
//! })?;
//! for exchange in exchanges {
//!     println!("{} {}", exchange.target_uri, exchange.response_metadata.status);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod cookies;
mod pow;
mod script;
mod session;
mod simply;
mod sucuri;
mod varnish_pow;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use archivindex_http_client::{CapturedExchange, Client};
use cookies::{CookieJar, StoredCookie};
use url::Url;

/// The maximum number of challenges a session answers during one fetch.
///
/// Callers using [`recognize`] directly should also bound repeated answers.
pub const MAX_CHALLENGE_ANSWERS: usize = 3;

/// An HTTP client and the challenge cookies retained between its requests.
///
/// Fetches answer at most [`MAX_CHALLENGE_ANSWERS`] challenges and preserve the original method,
/// headers, and body when repeating a request. Unknown challenges, truncated responses, and refused
/// verification responses end the sequence. Redirects also end it unless following is enabled.
/// Ordinary `Set-Cookie` fields are ignored.
#[derive(Clone, Debug)]
pub struct Session<C: Client> {
    client: C,
    cookies: Arc<Mutex<CookieJar>>,
    max_redirects: usize,
}

/// A failed session fetch, with every exchange completed before the failure.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct Error {
    /// Earlier exchanges, including challenge pages and verification responses, in request order.
    pub exchanges: Vec<CapturedExchange>,
    /// The transport, request preparation, or deadline error that ended the sequence.
    #[source]
    pub source: archivindex_http_client::Error,
}

/// A recognized challenge and the answer needed to continue.
#[derive(Clone, Debug)]
pub enum Challenge {
    /// Send these cookies when repeating the request.
    Cookie(StoredCookie),
    /// Submit this proof of work and read the clearance cookie from its response.
    ProofOfWork(ProofOfWork),
}

/// A solved Simply.com proof of work, ready to submit for a clearance cookie.
///
/// POST [`request_body`](Self::request_body) to [`verification_url`](Self::verification_url)
/// with content type `application/x-www-form-urlencoded`. The URL is on the challenged origin
/// and has the path `/.sc-verify/`. Use [`clearance_cookie`](Self::clearance_cookie) to read the
/// answer before repeating the original request.
#[derive(Clone, Debug)]
pub struct ProofOfWork {
    token: String,
    timestamp: String,
    nonce: u64,
    verification_url: Url,
}

/// Recognize and solve a challenge in a complete captured response.
///
/// The captured target identifies the challenged origin. Proof-of-work searches test at most
/// ten million candidates and check `deadline` before each batch of 256 attempts. `None` means
/// the response is unrecognized, malformed, truncated, or beyond the supported work limits, or
/// the deadline has passed. Content coding is not decoded.
#[must_use]
pub fn recognize(captured: &CapturedExchange, deadline: Option<Instant>) -> Option<Challenge> {
    if captured.truncated.is_some() || deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return None;
    }
    let url = Url::parse(captured.target_uri.as_str()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    sucuri::recognize(captured, &url)
        .or_else(|| varnish_pow::recognize(captured, &url, deadline))
        .or_else(|| simply::recognize(captured, &url, deadline))
}

/// The purpose of a request about to be sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// An initial resource request, redirect hop, or repeat after obtaining clearance.
    Resource,
    /// A proof submitted to obtain clearance, independent of resource validators.
    Verification,
}

/// Request preparation after cookie resolution, and delivery of every completed exchange.
pub trait Observer {
    /// A preparation failure that stops the sequence without discarding earlier exchanges.
    type Error;

    /// Prepare fields after cookies are resolved and before the client receives the request.
    fn prepare(
        &mut self,
        method: &http::Method,
        target: &http::Uri,
        headers: &mut http::HeaderMap,
        kind: RequestKind,
    ) -> Result<(), Self::Error>;

    /// Receive a completed exchange, including redirects and proof verification responses.
    fn captured(&mut self, exchange: CapturedExchange, method: &http::Method);
}

/// A sequence stopped because preparation or fetching failed. Earlier exchanges were observed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError<E> {
    /// Request preparation, transport, or deadline failure.
    #[error(transparent)]
    Client(#[from] archivindex_http_client::Error),
    /// The observer refused a request.
    #[error("request preparation failed: {0}")]
    Observer(E),
}
