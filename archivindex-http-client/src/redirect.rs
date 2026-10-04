//! Redirect locations and request rewriting using common user-agent semantics.

use http::header::{
    AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, PROXY_AUTHORIZATION,
    TRANSFER_ENCODING,
};
use http::{HeaderMap, Method};
use url::Url;

/// Prepare the next request in a redirect chain using common user-agent semantics.
///
/// `POST` becomes `GET` after `301`, `302`, or `303`; other methods become `GET` after `303`. `307`
/// and `308` preserve the method and body. Authority-specific fields, a caller-supplied `Host`
/// among them, are not forwarded to another origin; a redirect within one origin keeps them, so
/// that a crawl addressing a virtual host by IP address goes on reaching it.
pub fn redirect_request(
    current: &Url,
    next: &Url,
    status: u16,
    method: &mut Method,
    headers: &mut HeaderMap,
    body: &mut Option<Vec<u8>>,
) {
    if current.origin() != next.origin() {
        headers.remove(HOST);
        headers.remove(AUTHORIZATION);
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove(COOKIE);
    }

    let becomes_get = (matches!(status, 301 | 302) && *method == Method::POST)
        || (status == 303 && *method != Method::HEAD);
    if becomes_get {
        *method = Method::GET;
        *body = None;
        headers.remove(CONTENT_LENGTH);
        headers.remove(CONTENT_TYPE);
        headers.remove(TRANSFER_ENCODING);
    }
}

/// Whether a status redirects to the response's `Location`.
const fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// The redirect target of a response, when present and followable over HTTP.
#[must_use]
pub fn next_location(current: &Url, status: u16, location: Option<&str>) -> Option<Url> {
    if !is_redirect(status) {
        return None;
    }

    let next = current.join(location?).ok()?;
    (matches!(next.scheme(), "http" | "https")
        && next.username().is_empty()
        && next.password().is_none())
    .then_some(next)
}
