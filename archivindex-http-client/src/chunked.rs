//! Chunk framing for response bodies a client receives already decoded.
//!
//! A client that reconstructs a chunked response writes each piece of body data it receives as
//! one chunk, so the stored message keeps the framing its header section declares.

use http::{HeaderMap, header};

/// Whether `headers` declare `chunked` as the final transfer coding.
///
/// This is the test [`ResponseCapture`](crate::framing::ResponseCapture) applies to a stored
/// header section, so a body written as chunks whenever it holds is framed as the capture expects.
pub fn is_declared(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .next_back()
        .and_then(|value| value.as_bytes().rsplit(|byte| *byte == b',').next())
        .is_some_and(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

/// The chunk-size line that opens a chunk of `length` bytes.
pub fn size_line(length: usize) -> String {
    format!("{length:x}\r\n")
}

/// The last chunk and the trailer section that closes the body.
pub fn last_chunk(trailers: &HeaderMap) -> Vec<u8> {
    let mut bytes = Vec::from(&b"0\r\n"[..]);
    for (name, value) in trailers {
        bytes.extend_from_slice(name.as_str().as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");

    bytes
}
