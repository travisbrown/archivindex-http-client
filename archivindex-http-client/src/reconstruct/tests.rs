use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode, Uri, Version};

use super::{Error, reconstruct_request, reconstruct_response};

fn headers(lines: &[(&'static str, &'static str)]) -> HeaderMap {
    lines
        .iter()
        .map(|(name, value)| {
            (
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            )
        })
        .collect()
}

/// A recorded body replaces transfer coding with length framing.
#[test]
fn response_with_a_body_rewrites_its_framing() {
    let message = reconstruct_response(
        Version::HTTP_11,
        StatusCode::OK,
        &headers(&[
            ("content-type", "text/plain"),
            ("transfer-encoding", "chunked"),
            ("content-length", "999"),
        ]),
        Some(b"hello world!"),
    )
    .unwrap();

    assert_eq!(
        message,
        b"HTTP/1.1 200 OK\r\n\
          content-type: text/plain\r\n\
          content-length: 12\r\n\
          \r\n\
          hello world!"
    );
}

/// The status line retains its required space when no reason phrase is available.
#[test]
fn status_line_keeps_its_space_without_a_reason_phrase() {
    let message = reconstruct_response(
        Version::HTTP_11,
        StatusCode::from_u16(520).unwrap(),
        &HeaderMap::new(),
        Some(b"?"),
    )
    .unwrap();

    assert_eq!(message, b"HTTP/1.1 520 \r\ncontent-length: 1\r\n\r\n?");
}

/// A bodyless status preserves headers that describe the selected representation.
#[test]
fn bodiless_status_preserves_its_headers() {
    for body in [None, Some(&b""[..])] {
        let message = reconstruct_response(
            Version::HTTP_11,
            StatusCode::NOT_MODIFIED,
            &headers(&[("content-length", "1234"), ("etag", "\"abc\"")]),
            body,
        )
        .unwrap();

        assert_eq!(
            message,
            b"HTTP/1.1 304 Not Modified\r\n\
              content-length: 1234\r\n\
              etag: \"abc\"\r\n\
              \r\n"
        );
    }
}

/// A bodyless status rejects a non-empty body.
#[test]
fn bodiless_status_refuses_a_body() {
    let error = reconstruct_response(
        Version::HTTP_11,
        StatusCode::NO_CONTENT,
        &HeaderMap::new(),
        Some(b"x"),
    )
    .unwrap_err();

    assert_eq!(error, Error::BodyForbidden(StatusCode::NO_CONTENT));
    assert_eq!(
        error.to_string(),
        "a 204 No Content response cannot carry a body"
    );
}

/// An absent body preserves framing headers.
#[test]
fn absent_body_preserves_framing_headers() {
    let message = reconstruct_response(
        Version::HTTP_11,
        StatusCode::OK,
        &headers(&[("content-length", "5")]),
        None,
    )
    .unwrap();

    assert_eq!(message, b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n");
}

/// Versions without an HTTP/1.1 wire form are written with the `HTTP/1.1` token.
#[test]
fn version_tokens() {
    for (version, expected) in [
        (Version::HTTP_09, &b"HTTP/0.9 200 OK\r\n\r\n"[..]),
        (Version::HTTP_10, b"HTTP/1.0 200 OK\r\n\r\n"),
        (Version::HTTP_11, b"HTTP/1.1 200 OK\r\n\r\n"),
        (Version::HTTP_2, b"HTTP/1.1 200 OK\r\n\r\n"),
        (Version::HTTP_3, b"HTTP/1.1 200 OK\r\n\r\n"),
    ] {
        let message =
            reconstruct_response(version, StatusCode::OK, &HeaderMap::new(), None).unwrap();

        assert_eq!(message, expected, "{version:?}");
    }
}

/// Entity-body extraction recovers the recorded body.
#[test]
fn entity_body_reads_back_the_recorded_body() {
    let body: &[u8] = b"the recorded body";
    let message = reconstruct_response(
        Version::HTTP_11,
        StatusCode::OK,
        &headers(&[("transfer-encoding", "chunked")]),
        Some(body),
    )
    .unwrap();

    assert_eq!(crate::body::entity_body(&message).unwrap().as_ref(), body);
}

/// Origin-form retains the query and leaves the authority in `Host`.
#[test]
fn request_target_is_written_in_origin_form() {
    let target: Uri = "http://example.com/a/b?q=1".parse().unwrap();
    let message = reconstruct_request(
        &Method::GET,
        &target,
        Version::HTTP_11,
        &headers(&[("host", "example.com")]),
        None,
    );

    assert_eq!(
        message,
        b"GET /a/b?q=1 HTTP/1.1\r\nhost: example.com\r\n\r\n"
    );
}

/// A target with no path names the root resource.
#[test]
fn request_target_defaults_to_the_root() {
    let target: Uri = "http://example.com".parse().unwrap();
    let message = reconstruct_request(
        &Method::GET,
        &target,
        Version::HTTP_11,
        &HeaderMap::new(),
        None,
    );

    assert_eq!(message, b"GET / HTTP/1.1\r\n\r\n");
}

/// A `CONNECT` target is the authority to open a tunnel to, which has no path to write.
#[test]
fn connect_request_target_is_written_in_authority_form() {
    let target: Uri = "https://example.com:443".parse().unwrap();
    let message = reconstruct_request(
        &Method::CONNECT,
        &target,
        Version::HTTP_11,
        &headers(&[("host", "example.com:443")]),
        None,
    );

    assert_eq!(
        message,
        b"CONNECT example.com:443 HTTP/1.1\r\nhost: example.com:443\r\n\r\n"
    );
}

/// A matching `Content-Length` remains in place.
#[test]
fn matching_content_length_is_kept_in_place() {
    let message = reconstruct_response(
        Version::HTTP_11,
        StatusCode::OK,
        &headers(&[("content-length", "5"), ("server", "test")]),
        Some(b"hello"),
    )
    .unwrap();

    assert_eq!(
        message,
        b"HTTP/1.1 200 OK\r\n\
          content-length: 5\r\n\
          server: test\r\n\
          \r\n\
          hello"
    );
}

/// A recorded request body is framed by its length, like a response body.
#[test]
fn request_with_a_body_rewrites_its_framing() {
    let target: Uri = "/submit".parse().unwrap();
    let message = reconstruct_request(
        &Method::POST,
        &target,
        Version::HTTP_11,
        &headers(&[("host", "example.com"), ("transfer-encoding", "chunked")]),
        Some(b"hello"),
    );

    assert_eq!(
        message,
        b"POST /submit HTTP/1.1\r\n\
          host: example.com\r\n\
          content-length: 5\r\n\
          \r\n\
          hello"
    );
}
