use std::borrow::Cow;

use super::{RequestMetadata, ResponseMetadata};

#[test]
fn response_metadata_preserves_boundaries_and_header_values() {
    let response = b"HTTP/1.1 206 Partial Content\r\nX-Test: first\r\nx-test: second\r\nX-Binary: \xff\r\n\r\nbody";
    let metadata = ResponseMetadata::parse(response).unwrap();

    assert_eq!(metadata.status, 206);
    assert_eq!(&response[metadata.body_offset..], b"body");
    assert_eq!(metadata.header("X-TEST"), Some(b"first".as_slice()));
    assert_eq!(metadata.header("x-binary"), Some(b"\xff".as_slice()));
}

#[test]
fn response_metadata_unfolds_continuation_lines() {
    let response = b"HTTP/1.0 200 OK\r\nX-Test: one\r\n\ttwo\r\n three\r\n\r\n";
    let metadata = ResponseMetadata::parse(response).unwrap();

    assert_eq!(metadata.header("x-test"), Some(b"one two three".as_slice()));
}

/// The head is framed as [`entity_body`](crate::body::entity_body) frames it, bare `LF` included.
#[test]
fn response_metadata_reads_lines_ended_with_a_bare_line_feed() {
    let response = b"HTTP/1.1 200 OK\nContent-Type: text/html\r\n\r\nhi";
    let metadata = ResponseMetadata::parse(response).unwrap();

    assert_eq!(metadata.status, 200);
    assert_eq!(
        metadata.header("content-type"),
        Some(b"text/html".as_slice())
    );
    assert_eq!(
        &response[metadata.body_offset..],
        crate::body::entity_body(response).unwrap().as_ref()
    );
}

#[test]
fn response_metadata_rejects_incomplete_or_malformed_messages() {
    assert!(ResponseMetadata::parse(b"HTTP/1.1 200 OK\r\nX: y\r\n").is_none());
    assert!(ResponseMetadata::parse(b"not HTTP\r\n\r\n").is_none());
    assert!(ResponseMetadata::parse(b"HTTP/1.1 20 OK\r\n\r\n").is_none());
}

/// Repeated fields are returned in receive order.
#[test]
fn repeated_response_headers_are_returned_in_order() {
    let response = b"HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\nvary: User-Agent\r\n\r\n";
    let metadata = ResponseMetadata::parse(response).unwrap();

    assert_eq!(
        metadata.headers("vary").collect::<Vec<_>>(),
        [b"Accept-Encoding".as_slice(), b"User-Agent".as_slice()]
    );
    assert_eq!(metadata.headers("etag").next(), None);
}

#[test]
fn request_metadata_preserves_boundaries_and_header_values() {
    let request = b"POST /submit?q=1 HTTP/1.1\r\nHost: example.com\r\n\
                    Content-Length: 4\r\nX-Binary: \xff\r\n\r\nbody";
    let metadata = RequestMetadata::parse(request).unwrap();

    assert_eq!(metadata.method(), "POST");
    assert_eq!(metadata.target(), b"/submit?q=1");
    assert_eq!(&request[metadata.body_offset..], b"body");
    assert_eq!(metadata.header("HOST"), Some(b"example.com".as_slice()));
    assert_eq!(metadata.header("x-binary"), Some(b"\xff".as_slice()));
    assert_eq!(metadata.header("accept"), None);
}

/// Request metadata exposes every field used to select a representation.
#[test]
fn request_metadata_reads_the_fields_that_select_a_representation() {
    let request = b"GET / HTTP/1.1\r\nUser-Agent: MobileBot/1.0\r\n\
                    Accept-Encoding: gzip\r\naccept-encoding: br\r\n\r\n";
    let metadata = RequestMetadata::parse(request).unwrap();

    assert_eq!(
        metadata.header("user-agent"),
        Some(b"MobileBot/1.0".as_slice())
    );
    assert_eq!(
        metadata.headers("Accept-Encoding").collect::<Vec<_>>(),
        [b"gzip".as_slice(), b"br".as_slice()]
    );
}

/// The lines of a repeated field combine into the value a `Vary` selection compares.
#[test]
fn combined_header_joins_the_lines_of_a_repeated_field() {
    let request = b"GET / HTTP/1.1\r\nAccept-Language: en\r\naccept-language: de\r\n\
                    User-Agent: Bot/1.0\r\nX-Binary: \xff\r\n\r\n";
    let metadata = RequestMetadata::parse(request).unwrap();

    assert_eq!(
        metadata.combined_header("accept-language"),
        Some(Cow::Owned("en, de".to_owned()))
    );
    assert_eq!(
        metadata.combined_header("user-agent"),
        Some(Cow::Borrowed("Bot/1.0"))
    );
    assert_eq!(metadata.combined_header("x-binary"), None);
    assert_eq!(metadata.combined_header("accept"), None);

    let response = b"HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\n\
                     vary: User-Agent\r\n\r\n";
    let metadata = ResponseMetadata::parse(response).unwrap();

    assert_eq!(
        metadata.combined_header("vary"),
        Some(Cow::Owned("Accept-Encoding, User-Agent".to_owned()))
    );
}

#[test]
fn request_metadata_unfolds_continuation_lines() {
    let request = b"GET / HTTP/1.1\r\nX-Test: one\r\n\ttwo\r\n three\r\n\r\n";
    let metadata = RequestMetadata::parse(request).unwrap();

    assert_eq!(metadata.header("x-test"), Some(b"one two three".as_slice()));
}

/// Origin, absolute, authority, and asterisk targets are accepted.
#[test]
fn request_metadata_accepts_every_request_target_form() {
    let targets: [&[u8]; 4] = [
        b"/origin",
        b"http://example.com/absolute",
        b"example.com:443",
        b"*",
    ];

    for target in targets {
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        let metadata = RequestMetadata::parse(&request).unwrap();

        assert_eq!(metadata.target(), target);
    }
}

#[test]
fn request_metadata_rejects_incomplete_or_malformed_messages() {
    // No terminating blank line.
    assert!(RequestMetadata::parse(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
    // A response, which a recorded request must not be.
    assert!(RequestMetadata::parse(b"HTTP/1.1 200 OK\r\n\r\n").is_none());
    // No version.
    assert!(RequestMetadata::parse(b"GET /\r\n\r\n").is_none());
    // A space in the target splits the request line.
    assert!(RequestMetadata::parse(b"GET /a b HTTP/1.1\r\n\r\n").is_none());
    // A method that is not a token.
    assert!(RequestMetadata::parse(b"GE(T / HTTP/1.1\r\n\r\n").is_none());
    assert!(RequestMetadata::parse(b" / HTTP/1.1\r\n\r\n").is_none());
    // A field line without a name.
    assert!(RequestMetadata::parse(b"GET / HTTP/1.1\r\nnocolon\r\n\r\n").is_none());
}

/// Invalid field names must not turn malformed heads into reusable HTTP metadata.
#[test]
fn metadata_rejects_invalid_field_names() {
    for name in ["", "Bad Name", "ETag ", "Bad\tName", "Bäd", "Bad(Name)"] {
        for start in ["GET / HTTP/1.1", "HTTP/1.1 200 OK"] {
            let message = format!("{start}\r\n{name}: value\r\n\r\n");
            assert!(
                RequestMetadata::parse(message.as_bytes()).is_none(),
                "{message:?}"
            );
            assert!(
                ResponseMetadata::parse(message.as_bytes()).is_none(),
                "{message:?}"
            );
        }
    }
}
