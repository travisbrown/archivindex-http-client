use std::io::{Cursor, ErrorKind, Read};

use super::{ResponseCapture, ResponseError, Truncation};
use crate::Error;
use crate::read::read_response;

fn read_all(
    response: &[u8],
    head_request: bool,
    max_length: Option<u64>,
) -> (Vec<u8>, Option<Truncation>) {
    read_response(&mut Cursor::new(response), head_request, max_length).expect("a response")
}

struct YieldAt<'a> {
    bytes: &'a [u8],
    first: usize,
    offset: usize,
}

impl Read for YieldAt<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.bytes[self.offset..];
        if remaining.is_empty() {
            return Ok(0);
        }
        let bound = if self.offset == 0 {
            self.first
        } else {
            remaining.len()
        };
        let length = output.len().min(remaining.len()).min(bound);
        output[..length].copy_from_slice(&remaining[..length]);
        self.offset += length;
        Ok(length)
    }
}

fn read_at_cap(response: &[u8], cap: usize) -> (Vec<u8>, Option<Truncation>) {
    read_response(
        &mut YieldAt {
            bytes: response,
            first: cap,
            offset: 0,
        },
        false,
        Some(cap as u64),
    )
    .expect("a response")
}

#[test]
fn every_chunked_split_and_wire_cap_preserves_the_same_prefix() {
    let response = b"HTTP/1.1 200 Odd\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=yes\r\na\0b\r\n2\r\ncd\r\n0\r\nX-End: yes\r\n\r\n";
    let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    for split in 0..=response.len() {
        for cap in head_end..=response.len() {
            let mut capture = ResponseCapture::new(false, Some(cap as u64));
            capture.push(&response[..split]).unwrap();
            capture.push(&response[split..]).unwrap();
            assert!(capture.is_done(), "split={split}, cap={cap}");
            let (bytes, truncated) = capture.into_parts();
            assert_eq!(bytes, response[..cap], "split={split}, cap={cap}");
            assert_eq!(
                truncated,
                (cap < response.len()).then_some(Truncation::Length)
            );
        }
    }
}

#[test]
fn a_content_length_body_ends_at_the_declared_length() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

/// A second message or a late transport failure cannot change a completed capture.
#[test]
fn completion_ignores_following_bytes_and_late_failures() {
    for (head, response) in [
        (
            true,
            b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n".as_slice(),
        ),
        (false, b"HTTP/1.1 204 No Content\r\n\r\n"),
        (false, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        (false, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        (
            false,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ),
    ] {
        let bytes = [response, b"HTTP/1.1 500 Unrelated\r\n\r\n"].concat();
        for split in 0..=bytes.len() {
            let mut capture = ResponseCapture::new(head, Some(response.len() as u64));
            capture.push(&bytes[..split]).unwrap();
            capture.push(&bytes[split..]).unwrap();
            assert!(capture.is_done());
            capture.end(Some(Truncation::Time)).unwrap();
            capture.push(b"more unrelated bytes").unwrap();
            assert_eq!(capture.into_parts(), (response.to_vec(), None));
        }
    }
}

/// A valid length can exceed addressable memory; the capture still retains only its bounded prefix.
#[test]
fn a_maximum_content_length_can_be_captured_with_a_small_limit() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx";
    assert_eq!(
        read_all(response, false, Some(response.len() as u64)),
        (response.to_vec(), Some(Truncation::Length))
    );
}

#[test]
fn a_chunked_body_is_recorded_verbatim_through_its_trailers() {
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
        4;ext=a\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn a_response_without_framing_extends_to_the_close() {
    let response = b"HTTP/1.1 200 OK\r\n\r\nunbounded";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn a_non_chunked_final_transfer_coding_extends_to_the_close() {
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 1\r\n\r\nmore than one";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn a_head_response_ends_with_its_header_section() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let (recorded, truncated) = read_all(response, true, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn an_interim_response_is_discarded() {
    let response = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n\
        HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    assert_eq!(truncated, None);
}

#[test]
fn an_unsolicited_upgrade_is_an_error() {
    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x02ok";
    let result = read_response(&mut Cursor::new(response), false, None);

    assert!(matches!(
        result,
        Err(Error::Response(ResponseError::UnsolicitedUpgrade))
    ));
}

#[test]
fn a_disconnect_inside_the_body_truncates_the_response() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, Some(Truncation::Disconnect));
}

#[test]
fn a_reset_retains_partial_responses_but_does_not_complete_close_delimited_ones() {
    struct Reset;
    impl Read for Reset {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(ErrorKind::ConnectionReset.into())
        }
    }
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nabc",
        b"HTTP/1.1 200 OK\r\n\r\nabc",
    ] {
        let (bytes, truncated) = read_response(&mut response.chain(Reset), false, None).unwrap();
        assert_eq!(bytes, response);
        assert_eq!(truncated, Some(Truncation::Disconnect));
    }
    assert!(read_response(&mut b"HTTP/1.1".as_slice().chain(Reset), false, None).is_err());
    let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    assert_eq!(
        read_response(&mut complete.as_slice().chain(Reset), false, None).unwrap(),
        (complete.to_vec(), None)
    );
}

#[test]
fn the_length_bound_cuts_the_body_and_declares_the_reason() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let (recorded, truncated) = read_all(response, false, Some(40));

    assert_eq!(recorded, &response[..40]);
    assert_eq!(truncated, Some(Truncation::Length));
}

#[test]
fn an_exact_length_bound_marks_each_incomplete_framing() {
    let length = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcdefghij";
    let chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nabcdefghij\r\n0\r\n\r\n";
    let close = b"HTTP/1.1 200 OK\r\n\r\nabcdefghij";

    for (response, cap) in [
        (length.as_slice(), length.len() - 5),
        (chunked.as_slice(), chunked.len() - 10),
        (close.as_slice(), close.len() - 5),
    ] {
        let (recorded, truncated) = read_at_cap(response, cap);
        assert_eq!(recorded, &response[..cap]);
        assert_eq!(truncated, Some(Truncation::Length));
    }
}

#[test]
fn close_delimited_eof_exactly_at_the_bound_is_complete() {
    let response = b"HTTP/1.1 200 OK\r\n\r\ncomplete";
    let (recorded, truncated) = read_all(response, false, Some(response.len() as u64));

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn a_header_section_over_the_length_bound_is_an_error() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let result = read_response(&mut Cursor::new(response), false, Some(10));

    assert!(matches!(
        result,
        Err(Error::Response(ResponseError::OversizedHeaderSection))
    ));
}

#[test]
fn conflicting_content_lengths_are_an_error() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    let result = read_response(&mut Cursor::new(response), false, None);

    assert!(matches!(
        result,
        Err(Error::Response(ResponseError::ConflictingContentLength))
    ));
}

#[test]
fn repeated_identical_content_lengths_agree() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn a_malformed_chunk_size_is_an_error() {
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n";
    let result = read_response(&mut Cursor::new(response), false, None);

    assert!(matches!(
        result,
        Err(Error::Response(ResponseError::MalformedChunkSize(size))) if size == "xyz"
    ));
}

#[test]
fn a_missing_status_line_is_an_error() {
    let response = b"ICY 200 OK\r\n\r\n";
    let result = read_response(&mut Cursor::new(response), false, None);

    assert!(matches!(
        result,
        Err(Error::Response(ResponseError::MalformedStatusLine))
    ));
}

#[test]
fn a_close_before_the_header_section_completes_is_an_error() {
    let response = b"HTTP/1.1 200 OK\r\nContent-";
    let result = read_response(&mut Cursor::new(response), false, None);

    assert!(matches!(
        result,
        Err(Error::Response(ResponseError::IncompleteHeaderSection))
    ));
}

#[test]
fn folded_header_lines_join_before_framing_is_read() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length:\r\n 5\r\n\r\nhello";
    let (recorded, truncated) = read_all(response, false, None);

    assert_eq!(recorded, response);
    assert_eq!(truncated, None);
}

#[test]
fn interim_headers_do_not_consume_the_final_response_limit() {
    let final_response = b"HTTP/1.1 204 No Content\r\n\r\n";
    let mut response = format!(
        "HTTP/1.1 103 Early Hints\r\nLink: {}\r\n\r\n",
        "x".repeat(128)
    )
    .into_bytes();
    response.extend_from_slice(final_response);
    for chunk_size in [1, 7, response.len()] {
        let mut capture = ResponseCapture::new(false, Some(final_response.len() as u64));
        for chunk in response.chunks(chunk_size) {
            capture.push(chunk).unwrap();
        }
        assert!(capture.is_done());
        assert_eq!(capture.into_parts(), (final_response.to_vec(), None));
    }
}

#[test]
fn content_lengths_require_ascii_decimal_digits() {
    for value in ["+5", "-5", "", "1e1", "\u{a0}5", "5\u{a0}"] {
        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\nhello");
        assert!(
            matches!(
                read_response(&mut response.as_bytes(), false, None),
                Err(Error::Response(ResponseError::MalformedContentLength(_)))
            ),
            "{value:?}"
        );
    }
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: \t005 \t\r\n\r\nhello";
    assert_eq!(read_all(response, false, None), (response.to_vec(), None));
}

#[test]
fn every_header_split_keeps_only_the_final_message() {
    for message in [
        b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
    ] {
        let mut wire = b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n".to_vec();
        wire.extend_from_slice(message);
        wire.extend_from_slice(b"not part of the response");
        for split in 0..=wire.len() {
            let mut capture = ResponseCapture::new(false, None);
            capture.push(&wire[..split]).unwrap();
            capture.push(&wire[split..]).unwrap();
            assert!(capture.is_done());
            assert_eq!(capture.into_parts(), (message.to_vec(), None));
        }
    }
}

#[test]
fn long_chunk_extensions_and_trailers_survive_fragmented_reads() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;name={}\r\nbody\r\n0\r\nX-Trailer: {}\r\n\r\n",
        "a".repeat(24 * 1024),
        "b".repeat(24 * 1024)
    );
    for chunk_size in [1, 3, 16, 8192] {
        let mut capture = ResponseCapture::new(false, None);
        for chunk in response.as_bytes().chunks(chunk_size) {
            capture.push(chunk).unwrap();
        }
        assert!(capture.is_done());
        assert_eq!(capture.into_parts(), (response.as_bytes().to_vec(), None));
    }
}
