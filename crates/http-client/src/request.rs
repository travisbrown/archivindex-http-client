//! Request preparation shared by the clients.

use std::borrow::Cow;

use http::uri::Authority;
use http::{HeaderMap, HeaderValue, Uri, header};

/// The target to send, which is `target` without its userinfo.
///
/// Credentials reach an origin only in an `authorization` header from the caller. `reqwest` and
/// `wreq` would otherwise turn userinfo into `Basic` credentials, which the recorder does not.
pub fn target(target: &Uri) -> Cow<'_, Uri> {
    let Some((_, host_port)) = target
        .authority()
        .and_then(|authority| authority.as_str().rsplit_once('@'))
    else {
        return Cow::Borrowed(target);
    };
    let mut parts = target.clone().into_parts();
    parts.authority = Some(
        host_port
            .parse()
            .expect("invariant violation: an authority failed without its userinfo"),
    );

    Cow::Owned(
        Uri::from_parts(parts).expect("invariant violation: a URI failed without its userinfo"),
    )
}

/// Copy `headers` with the fields every exchange needs, and without framing fields.
///
/// A `host` field naming `authority`, which is that of the [`target`] to send, comes first, and
/// `connection: close` comes last. Each is added only when the caller supplied no field of that
/// name.
///
/// `transfer-encoding` and `content-length` fields are left out, because the body given to a fetch
/// frames its request. A field that declared any other body would leave the origin waiting for
/// bytes that are never sent.
pub fn headers(authority: &Authority, headers: &HeaderMap) -> HeaderMap {
    let mut prepared = HeaderMap::with_capacity(headers.len() + 2);
    if !headers.contains_key(header::HOST) {
        prepared.insert(
            header::HOST,
            HeaderValue::from_str(authority.as_str())
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
