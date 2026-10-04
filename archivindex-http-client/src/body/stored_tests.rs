use super::{Decoding, Error, entity_body_with};

fn entity_body(message: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, Error> {
    entity_body_with(message, Decoding::Stored)
}

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

/// HTTP messages accept bare `LF` line endings; WARC headers require `CRLF`.
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

/// A chunked body may end immediately after its zero-length chunk.
#[test]
fn chunked_body_ending_at_its_last_chunk() {
    let message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";

    assert_eq!(entity_body(message).unwrap().as_ref(), b"abc");
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
        // A chunk after the first declares a size that is not one.
        (
            "3\r\nabc\r\nzz\r\ndef\r\n0\r\n\r\n",
            Error::MalformedChunkSize("zz".to_owned()),
        ),
        // The body ends inside the data of a chunk.
        ("5\r\nabc", Error::IncompleteChunkedBody),
        // The data of a chunk is not closed by a line ending.
        ("3\r\nabcdef\r\n0\r\n\r\n", Error::IncompleteChunkedBody),
        // No chunk closes the body.
        ("3\r\nabc\r\n", Error::IncompleteChunkedBody),
    ] {
        let message = [prefix.as_bytes(), body.as_bytes()].concat();

        assert_eq!(entity_body(&message).unwrap_err(), expected, "{body:?}");
    }
}

/// Capturing tools store dechunked bodies under the `Transfer-Encoding` the response carried,
/// which the payload digests of such records are computed over.
#[test]
fn body_declared_chunked_that_does_not_open_as_one_is_read_as_stored() {
    let prefix = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: -1\r\n\r\n";

    for body in [
        "<!doctype html>\r\n<title>a</title>",
        "zz\r\nabc\r\n0\r\n\r\n",
        "",
    ] {
        let message = [prefix.as_bytes(), body.as_bytes()].concat();

        assert_eq!(
            entity_body(&message).unwrap().as_ref(),
            body.as_bytes(),
            "{body:?}"
        );
    }
}
