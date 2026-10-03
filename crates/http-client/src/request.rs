//! Request preparation shared by the backends that send a request built from its parts.

use http::uri::Authority;
use http::{HeaderMap, HeaderValue, header};

/// Copy `headers` with the fields every exchange needs.
///
/// A `host` field naming `authority` without its userinfo comes first, and `connection: close`
/// comes last. Each is added only when the caller supplied no field of that name.
pub fn headers(authority: &Authority, headers: &HeaderMap) -> HeaderMap {
    let mut prepared = HeaderMap::with_capacity(headers.len() + 2);
    if !headers.contains_key(header::HOST) {
        let authority = authority.as_str();
        let host_port = authority.split('@').next_back().unwrap_or(authority);
        prepared.insert(
            header::HOST,
            HeaderValue::from_str(host_port)
                .expect("invariant violation: a URI authority failed as a header value"),
        );
    }
    for (name, value) in headers {
        prepared.append(name.clone(), value.clone());
    }
    if !headers.contains_key(header::CONNECTION) {
        prepared.append(header::CONNECTION, HeaderValue::from_static("close"));
    }

    prepared
}
