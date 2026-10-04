use super::{Error, entity_body};

/// Without transfer-coding, the bytes after the header section are the entity-body.
#[test]
fn body_of_an_unencoded_message() {
    let message = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    assert_eq!(entity_body(message).unwrap().as_ref(), b"hello");
}

/// A message ending after its headers has an empty entity-body.
#[test]
fn body_of_a_message_without_one() {
    let message = b"HTTP/1.1 204 No Content\r\n\r\n";

    assert_eq!(entity_body(message).unwrap().as_ref(), b"");
}

/// HTTP messages accept bare `LF` line endings.
#[test]
fn body_of_a_message_written_with_bare_line_feeds() {
    let message = b"HTTP/1.1 200 OK\nContent-Length: 5\n\nhello";

    assert_eq!(entity_body(message).unwrap().as_ref(), b"hello");
}

/// A header section without a closing empty line has no identifiable body.
#[test]
fn unterminated_headers() {
    for message in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\n".as_slice(),
        b"".as_slice(),
    ] {
        assert_eq!(
            entity_body(message).unwrap_err(),
            Error::UnterminatedHeaders,
            "{message:?}"
        );
    }
}

/// Chunk sizes, extensions, and trailers are framing and are removed.
#[test]
fn chunked_body_is_joined() {
    let message = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: chunked\r\n",
        "\r\n",
        "5;name=value\r\n",
        "hello\r\n",
        "2\r\n",
        " w\r\n",
        "5\r\n",
        "orld!\r\n",
        "0\r\n",
        "Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n",
        "\r\n",
    );

    assert_eq!(
        entity_body(message.as_bytes()).unwrap().as_ref(),
        b"hello world!"
    );
}

/// The `identity` coding leaves the body unchanged.
#[test]
fn identity_coding_is_dropped() {
    let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Identity\r\n\r\nhello";

    assert_eq!(entity_body(message).unwrap().as_ref(), b"hello");
}

/// Repeated and folded `Transfer-Encoding` fields form one comma-separated list.
#[test]
fn transfer_encoding_is_read_as_one_list() {
    let message = concat!(
        "HTTP/1.1 200 OK\r\n",
        "Transfer-Encoding: identity,\r\n",
        "\tchunked\r\n",
        "Transfer-Encoding: identity\r\n",
        "\r\n",
        "3\r\nabc\r\n0\r\n\r\n",
    );

    assert_eq!(entity_body(message.as_bytes()).unwrap().as_ref(), b"abc");
}

/// An unsupported coding is reported with the complete value that named it.
#[test]
fn unsupported_transfer_coding() {
    let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\nhello";

    assert_eq!(
        entity_body(message).unwrap_err(),
        Error::UnsupportedTransferCoding("gzip, chunked".to_owned())
    );
}

/// Content-coding is part of the entity-body and remains unchanged.
#[test]
fn content_coding_is_left_in_place() {
    let message = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b\x08";

    assert_eq!(entity_body(message).unwrap().as_ref(), b"\x1f\x8b\x08");
}

#[test]
fn malformed_chunked_bodies() {
    let prefix = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

    for (body, expected) in [
        // The body does not open with a chunk size.
        (
            "<!doctype html>\r\n<title>a</title>",
            Error::MalformedChunkSize("<!doctype html>".to_owned()),
        ),
        // A later chunk declares a size that is not one.
        (
            "3\r\nabc\r\nzz\r\ndef\r\n0\r\n\r\n",
            Error::MalformedChunkSize("zz".to_owned()),
        ),
        // The body ends inside its first chunk-size line. Its one byte is framing, so
        // returning it as the entity-body would report a body byte that never arrived.
        ("a", Error::IncompleteChunkedBody),
        // The body ends inside the data of a chunk.
        ("5\r\nabc", Error::IncompleteChunkedBody),
        // The data of a chunk is not closed by a line ending.
        ("3\r\nabcdef\r\n0\r\n\r\n", Error::IncompleteChunkedBody),
        // No chunk closes the body.
        ("3\r\nabc\r\n", Error::IncompleteChunkedBody),
        // The body ends at its last chunk, before the empty line that ends the trailer
        // section. Every body byte has arrived, but a client that decodes the body itself
        // reports this as a failure, so accepting it would depend on the client.
        ("3\r\nabc\r\n0\r\n", Error::IncompleteChunkedBody),
        // The trailer section is not closed.
        (
            "3\r\nabc\r\n0\r\nExpires: never\r\n",
            Error::IncompleteChunkedBody,
        ),
        // There is no body at all. Only the request method or the status can make that a
        // complete response, and neither is part of the message.
        ("", Error::IncompleteChunkedBody),
    ] {
        let message = [prefix.as_bytes(), body.as_bytes()].concat();

        assert_eq!(entity_body(&message).unwrap_err(), expected, "{body:?}");
    }
}

/// Every proper prefix of a chunked body is incomplete, even inside its first size line.
#[test]
fn incomplete_chunked_prefixes_are_never_entity_data() {
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let body = b"a;ext=yes\r\n0123456789\r\n0\r\nx-end: yes\r\n\r\n";
    for length in 0..body.len() {
        let message = [head.as_slice(), &body[..length]].concat();
        assert_eq!(
            entity_body(&message),
            Err(Error::IncompleteChunkedBody),
            "{length}"
        );
    }
    let message = [head.as_slice(), body].concat();
    assert_eq!(entity_body(&message).unwrap().as_ref(), b"0123456789");
}
