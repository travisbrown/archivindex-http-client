//! Request preparation shared by the clients that send a request built from its parts.

use http::uri::Authority;
use http::{HeaderMap, HeaderValue, header};

/// Copy `headers` with the fields every exchange needs, and without framing fields.
///
/// A `host` field naming `authority` without its userinfo comes first, and `connection: close`
/// comes last. Each is added only when the caller supplied no field of that name.
///
/// `transfer-encoding` and `content-length` fields are left out, because the body given to a fetch
/// frames its request. A field that declared any other body would leave the origin waiting for
/// bytes that are never sent.
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
        if name != header::TRANSFER_ENCODING && name != header::CONTENT_LENGTH {
            prepared.append(name.clone(), value.clone());
        }
    }
    if !headers.contains_key(header::CONNECTION) {
        prepared.append(header::CONNECTION, HeaderValue::from_static("close"));
    }

    prepared
}
