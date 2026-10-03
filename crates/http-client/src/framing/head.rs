//! The status line and the framing that a response header section declares.

use super::{ResponseError, find_crlf};

pub enum BodyFraming {
    /// The message ends with its header section.
    None,
    /// The body is this many bytes.
    Length(u64),
    /// The body is chunked, ending after the trailer section.
    Chunked,
    /// The body extends to the close of the connection.
    Close,
}

pub fn parse_status(buffer: &[u8]) -> Result<u16, ResponseError> {
    let line_end = find_crlf(buffer).ok_or(ResponseError::MalformedStatusLine)?;
    let mut parts = buffer[..line_end].splitn(3, |&byte| byte == b' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();

    if !version.starts_with(b"HTTP/") || code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(ResponseError::MalformedStatusLine);
    }

    Ok(code
        .iter()
        .fold(0, |value, &byte| value * 10 + u16::from(byte - b'0')))
}

/// Determine response framing according to RFC 9112 section 6.3.
///
/// `Transfer-Encoding` overrides `Content-Length`. A final coding other than `chunked`, or no
/// framing fields, makes the response close-delimited.
pub fn body_framing(
    header_section: &[u8],
    head_request: bool,
    status: u16,
) -> Result<BodyFraming, ResponseError> {
    if head_request || status == 204 || status == 304 {
        return Ok(BodyFraming::None);
    }

    // Join obsolete line folds before parsing fields; the recorded bytes remain unchanged.
    let text = String::from_utf8_lossy(header_section)
        .replace("\r\n ", " ")
        .replace("\r\n\t", " ");

    let mut final_coding: Option<String> = None;
    let mut content_length: Option<u64> = None;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if let Some(coding) = value.split(',').next_back() {
                final_coding = Some(coding.trim().to_ascii_lowercase());
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            for token in value.split(',') {
                let token = token.trim_matches([' ', '\t']);
                if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ResponseError::MalformedContentLength(token.to_owned()));
                }
                let length = token
                    .parse::<u64>()
                    .map_err(|_| ResponseError::MalformedContentLength(token.to_owned()))?;
                if content_length
                    .replace(length)
                    .is_some_and(|seen| seen != length)
                {
                    return Err(ResponseError::ConflictingContentLength);
                }
            }
        }
    }

    Ok(match (final_coding, content_length) {
        (Some(coding), _) if coding == "chunked" => BodyFraming::Chunked,
        (Some(_), _) | (None, None) => BodyFraming::Close,
        (None, Some(length)) => BodyFraming::Length(length),
    })
}
