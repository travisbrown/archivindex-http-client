//! HTTP entity-body extraction.
//!
//! The entity-body of a stored message is its message body after transfer-coding has been removed.

use std::borrow::Cow;

use crate::parsing::{is_lws, lossy, next_line, split_field_line};

const TRANSFER_ENCODING: &[u8] = b"transfer-encoding";

const CHUNKED: &[u8] = b"chunked";

const IDENTITY: &[u8] = b"identity";

/// Errors returned while extracting an HTTP entity-body.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The header section has no terminating empty line.
    #[error("the HTTP message does not end its header section with an empty line")]
    UnterminatedHeaders,
    /// The message uses an unsupported transfer-coding.
    #[error("the HTTP message declares the transfer-coding `{0}`, which this crate cannot remove")]
    UnsupportedTransferCoding(String),
    /// A chunk has an invalid size line.
    #[error("the chunked message declares `{0}` where a chunk size belongs")]
    MalformedChunkSize(String),
    /// The chunked body is incomplete.
    #[error("the chunked message ends before the chunk that closes it")]
    IncompleteChunkedBody,
}

/// Extract the HTTP entity-body defined by RFC 2616 section 7.2.
///
/// Chunk framing and trailers are removed. `identity` is ignored, while content-coding is
/// preserved. The stored bytes frame `message`, so the HTTP `Content-Length` is not read. If no
/// decoding is needed, the returned value borrows from `message`.
///
/// A body declared chunked must be complete, through the empty line that ends its trailer section.
/// The message alone does not say whether it has a body at all, which depends on the request method
/// and the status, so use [`CapturedExchange::entity_body`](crate::CapturedExchange::entity_body)
/// for a captured response.
///
/// # Errors
///
/// Returns an error for an unterminated header section, invalid or incomplete chunk framing, or an
/// unsupported transfer-coding. This does not fully validate HTTP headers.
pub fn entity_body(message: &[u8]) -> Result<Cow<'_, [u8]>, Error> {
    entity_body_with(message, Decoding::Strict)
}

/// How transfer framing is interpreted in a stored HTTP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decoding {
    /// Require complete chunk framing, including the trailer terminator.
    Strict,
    /// Accept already-dechunked bodies with stale transfer headers and omitted trailers.
    ///
    /// A body that does not open with a chunk size is returned as stored. A zero-size chunk
    /// ends decoding even if its trailers are missing. Content coding is always preserved.
    Stored,
}

/// Extract an entity-body using an explicit transfer-decoding policy.
///
/// Unsupported codings and incomplete chunk data are errors under either policy.
pub fn entity_body_with(message: &[u8], policy: Decoding) -> Result<Cow<'_, [u8]>, Error> {
    let (body, transfer_encoding) = split_message(message)?;
    if is_chunked(&transfer_encoding)?
        && (policy == Decoding::Strict
            || next_line(body, 0).is_some_and(|line| chunk_size(&body[..line.end]).is_ok()))
    {
        Ok(Cow::Owned(dechunk(body, policy)?))
    } else {
        Ok(Cow::Borrowed(body))
    }
}

/// Return the stored message body without transfer decoding or HTTP length enforcement.
pub fn message_body(message: &[u8]) -> Result<&[u8], Error> {
    split_message(message).map(|(body, _)| body)
}

/// Split an HTTP message into its body and combined `Transfer-Encoding` value.
///
/// Repeated and folded fields are combined into one comma-separated value.
fn split_message(message: &[u8]) -> Result<(&[u8], Vec<u8>), Error> {
    // Skip the HTTP start line.
    let mut offset = next_line(message, 0)
        .ok_or(Error::UnterminatedHeaders)?
        .next;
    let mut transfer_encoding = Vec::new();
    let mut folding = false;

    loop {
        let line = next_line(message, offset).ok_or(Error::UnterminatedHeaders)?;
        let content = &message[offset..line.end];
        offset = line.next;

        if content.is_empty() {
            return Ok((&message[offset..], transfer_encoding));
        }

        if content.first().copied().is_some_and(is_lws) {
            // Folded lines continue the preceding field.
            if folding {
                transfer_encoding.push(b' ');
                transfer_encoding.extend_from_slice(content);
            }
            continue;
        }

        folding = false;
        if let Some((name, colon)) = split_field_line(content)
            && name.eq_ignore_ascii_case(TRANSFER_ENCODING)
        {
            if !transfer_encoding.is_empty() {
                transfer_encoding.push(b',');
            }
            transfer_encoding.extend_from_slice(&content[colon + 1..]);
            folding = true;
        }
    }
}

/// Check whether `Transfer-Encoding` requests chunk decoding.
///
/// Empty elements and `identity` are ignored. No coding may follow `chunked`.
fn is_chunked(transfer_encoding: &[u8]) -> Result<bool, Error> {
    let mut chunked = false;

    for coding in transfer_encoding.split(|&byte| byte == b',') {
        let coding = coding.trim_ascii();
        if coding.is_empty() || coding.eq_ignore_ascii_case(IDENTITY) {
            continue;
        }
        if chunked || !coding.eq_ignore_ascii_case(CHUNKED) {
            return Err(Error::UnsupportedTransferCoding(lossy(
                transfer_encoding.trim_ascii(),
            )));
        }
        chunked = true;
    }

    Ok(chunked)
}

/// Decode a chunked body as defined by RFC 2616 section 3.6.1.
///
/// Chunk extensions, framing, and trailers are omitted from the result.
fn dechunk(body: &[u8], policy: Decoding) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::with_capacity(body.len());
    let mut offset = 0;

    loop {
        let line = next_line(body, offset).ok_or(Error::IncompleteChunkedBody)?;
        let size = chunk_size(&body[offset..line.end])?;
        offset = line.next;

        if size == 0 {
            if policy == Decoding::Stored {
                return Ok(decoded);
            }
            // The trailer section ends at an empty line, which a complete body includes.
            loop {
                let line = next_line(body, offset).ok_or(Error::IncompleteChunkedBody)?;
                if line.end == offset {
                    return Ok(decoded);
                }
                offset = line.next;
            }
        }

        let end = offset
            .checked_add(size)
            .filter(|end| *end <= body.len())
            .ok_or(Error::IncompleteChunkedBody)?;
        decoded.extend_from_slice(&body[offset..end]);

        // The chunk data must be followed immediately by a line ending.
        let line = next_line(body, end).ok_or(Error::IncompleteChunkedBody)?;
        if line.end != end {
            return Err(Error::IncompleteChunkedBody);
        }
        offset = line.next;
    }
}

/// Parse a hexadecimal chunk size, ignoring extensions.
fn chunk_size(line: &[u8]) -> Result<usize, Error> {
    let digits = line
        .iter()
        .position(|&byte| byte == b';')
        .map_or(line, |extensions| &line[..extensions])
        .trim_ascii();

    std::str::from_utf8(digits)
        .ok()
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|digits| usize::from_str_radix(digits, 16).ok())
        .ok_or_else(|| Error::MalformedChunkSize(lossy(line)))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod stored_tests;
