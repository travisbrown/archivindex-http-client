//! HTTP/1.1 message reconstruction from parsed parts.
//!
//! These functions rebuild HTTP/1.1 messages for HTTP libraries that expose parsed parts but not
//! the serialized message. Reconstruction uses the [`http`] crate's lowercased header names and the
//! status code's canonical reason phrase; providing a body also rewrites its framing. A
//! reconstructed message is therefore not the bytes the origin sent.
//!
//! A provided body is framed by `content-length` after any `Transfer-Encoding` is removed. Reading
//! the message with [`entity_body`](crate::body::entity_body) recovers that body.

use http::{HeaderMap, Method, StatusCode, Uri, Version};

/// Errors returned while reconstructing an HTTP message.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// A non-empty body was provided for a status that forbids one.
    #[error("a {0} response cannot carry a body")]
    BodyForbidden(StatusCode),
}

/// Reconstruct an HTTP/1.1 response message from parsed parts.
///
/// With `body` set to `None`, framing headers are preserved (for example, for a response to a
/// `HEAD` request). A provided body must have transfer coding removed. Reconstruction removes
/// `Transfer-Encoding` and writes its length unless a lone `Content-Length` already matches.
///
/// Informational, `204`, and `304` responses cannot contain a body. Their headers are preserved; in
/// particular, a `304` may describe the selected representation with `Content-Length`.
///
/// HTTP/2 and later have no HTTP/1.1 wire form, so their parts use the `HTTP/1.1` version token.
///
/// # Errors
///
/// Returns [`Error::BodyForbidden`] if the status forbids a non-empty body.
pub fn reconstruct_response(
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let body = match body {
        Some(body) if forbids_body(status) => {
            if body.is_empty() {
                None
            } else {
                return Err(Error::BodyForbidden(status));
            }
        }
        body => body,
    };

    let reason = status.canonical_reason().unwrap_or_default();
    let mut message = Vec::with_capacity(16 + reason.len() + header_capacity(headers, body));

    message.extend_from_slice(version_token(version).as_bytes());
    message.push(b' ');
    message.extend_from_slice(status.as_str().as_bytes());
    // The space is mandatory even when no reason phrase follows it (RFC 9112 section 4).
    message.push(b' ');
    message.extend_from_slice(reason.as_bytes());
    message.extend_from_slice(b"\r\n");

    write_headers_and_body(&mut message, headers, body);

    Ok(message)
}

/// Reconstruct an HTTP/1.1 request message from parsed parts.
///
/// The target is written in origin-form, for which `headers` must contain the authority in `Host`,
/// except under `CONNECT`, which takes the authority-form RFC 9112 section 3.2.3 defines. With
/// `body` set to `None`, headers are preserved. For a provided body, `Transfer-Encoding` is removed
/// and the length is written unless a lone `Content-Length` already matches.
///
/// HTTP/2 and later have no HTTP/1.1 wire form, so their parts use the `HTTP/1.1` version token.
pub fn reconstruct_request(
    method: &Method,
    target: &Uri,
    version: Version,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let target = if method == Method::CONNECT {
        target.authority().map_or("/", http::uri::Authority::as_str)
    } else {
        target
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
    };
    let mut message = Vec::with_capacity(
        method.as_str().len() + target.len() + 12 + header_capacity(headers, body),
    );

    message.extend_from_slice(method.as_str().as_bytes());
    message.push(b' ');
    message.extend_from_slice(target.as_bytes());
    message.push(b' ');
    message.extend_from_slice(version_token(version).as_bytes());
    message.extend_from_slice(b"\r\n");

    write_headers_and_body(&mut message, headers, body);

    message
}

fn forbids_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

const fn version_token(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    }
}

fn header_capacity(headers: &HeaderMap, body: Option<&[u8]>) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum::<usize>()
        + body.map_or(0, |body| body.len() + 24)
        + 2
}

fn framing_matches(headers: &HeaderMap, body: &[u8]) -> bool {
    let mut lengths = headers.get_all(http::header::CONTENT_LENGTH).iter();

    matches!(
        (lengths.next(), lengths.next()),
        (Some(value), None)
            if value
                .to_str()
                .is_ok_and(|value| value.trim().parse() == Ok(body.len() as u64))
    )
}

fn write_headers_and_body(message: &mut Vec<u8>, headers: &HeaderMap, body: Option<&[u8]>) {
    let keep_length = body.is_none_or(|body| framing_matches(headers, body));

    for (name, value) in headers {
        if body.is_some()
            && (name == http::header::TRANSFER_ENCODING
                || (name == http::header::CONTENT_LENGTH && !keep_length))
        {
            continue;
        }

        message.extend_from_slice(name.as_str().as_bytes());
        message.extend_from_slice(b": ");
        message.extend_from_slice(value.as_bytes());
        message.extend_from_slice(b"\r\n");
    }

    if let Some(body) = body {
        if !keep_length {
            message.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
        }

        message.extend_from_slice(b"\r\n");
        message.extend_from_slice(body);
    } else {
        message.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests;
