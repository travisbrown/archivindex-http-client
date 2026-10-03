//! Message framing shared by every capture backend.
//!
//! [`ResponseCapture`] turns received bytes into the stored response of one exchange. It owns the
//! rules that decide where a response ends, when it is complete, and why it was cut short, so any
//! backend driving it records the same bytes as any other.

mod chunk;
mod head;

use chunk::ChunkScanner;
use head::{BodyFraming, body_framing, parse_status};

const MAX_HEADER_LENGTH: usize = 64 * 1024;

/// Why a stored response ends before its message boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Truncation {
    /// The response reached the bound on stored response bytes.
    Length,
    /// A read timeout or the fetch deadline passed.
    Time,
    /// The transport ended before the message did.
    Disconnect,
}

/// Malformed responses whose message boundary cannot be determined.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResponseError {
    /// The response does not begin with an HTTP status line.
    #[error("the response does not begin with an HTTP status line")]
    MalformedStatusLine,
    /// The server switched protocols with a `101` the request did not ask for.
    #[error("the server switched protocols with a `101` the request did not ask for")]
    UnsolicitedUpgrade,
    /// The connection ended before a complete header section arrived.
    #[error("the connection ended before a complete response header section arrived")]
    IncompleteHeaderSection,
    /// The header section exceeds the limit on stored head bytes.
    #[error("the response header section exceeds the limit on stored head bytes")]
    OversizedHeaderSection,
    /// The response declares `Content-Length` values that disagree.
    #[error("the response declares `Content-Length` values that disagree")]
    ConflictingContentLength,
    /// A declared `Content-Length` is not a valid decimal length.
    #[error("the declared `Content-Length` `{0}` is not a valid decimal length")]
    MalformedContentLength(String),
    /// A declared chunk size is not a valid hexadecimal length.
    #[error("the declared chunk size `{0}` is not a hexadecimal length")]
    MalformedChunkSize(String),
    /// A chunk's data is not followed by the terminating CRLF.
    #[error("a chunk's data is not followed by CRLF")]
    UnterminatedChunk,
}

/// Incremental capture of one response's wire bytes, shared by every backend.
///
/// Feed it transport reads with [`push`](Self::push) and close it with [`end`](Self::end). The
/// final response is bounded by the configured cap. Interim headers have a separate 64 KiB bound
/// and are discarded, so every backend uses the same framing, truncation, and byte content.
pub struct ResponseCapture {
    buffer: Vec<u8>,
    head_request: bool,
    cap: Option<u64>,
    framing: Option<BodyFraming>,
    header_end: usize,
    scanner: Option<ChunkScanner>,
    done: bool,
    truncated: Option<Truncation>,
}

impl ResponseCapture {
    /// Start a capture.
    ///
    /// Set `head_request` when the request method was `HEAD`, so that a declared body length is
    /// not awaited. `cap` bounds retained wire bytes, including the header section.
    #[must_use]
    pub const fn new(head_request: bool, cap: Option<u64>) -> Self {
        Self {
            buffer: Vec::new(),
            head_request,
            cap,
            framing: None,
            header_end: 0,
            scanner: None,
            done: false,
            truncated: None,
        }
    }

    /// Whether the response is complete, capped, or truncated, so no further bytes are wanted.
    ///
    /// A backend should stop reading and dispose of its connection once this is true.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// Feed newly received bytes.
    ///
    /// Extra bytes beyond the cap provide length evidence but are never stored. Interim heads
    /// have their own bound and do not consume the final cap. Bytes offered after the capture is
    /// done are ignored.
    ///
    /// # Errors
    ///
    /// Fails when the response cannot be framed, including an oversized or malformed header
    /// section and malformed chunk framing.
    ///
    /// # Panics
    ///
    /// Panics only if a message boundary already inside the buffer does not fit in a `usize`,
    /// which the cap and the buffer's own length make impossible.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), ResponseError> {
        while self.framing.is_none() && !bytes.is_empty() && !self.done {
            if self.buffer.len() >= MAX_HEADER_LENGTH {
                return Err(ResponseError::OversizedHeaderSection);
            }
            // A head can end only at LF. Copy a line fragment at a time, retaining the suffix
            // across transport reads so split delimiters and coalesced interim heads work alike.
            if let [byte] = bytes {
                self.buffer.push(*byte);
                bytes = &[];
            } else {
                let length = bytes
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |index| index + 1)
                    .min(MAX_HEADER_LENGTH - self.buffer.len());
                self.buffer.extend_from_slice(&bytes[..length]);
                bytes = &bytes[length..];
            }
            if !self.buffer.ends_with(b"\r\n\r\n") {
                continue;
            }
            let status = parse_status(&self.buffer)?;
            if status == 101 {
                return Err(ResponseError::UnsolicitedUpgrade);
            }
            if (100..200).contains(&status) {
                self.buffer.clear();
                continue;
            }
            if self.cap.is_some_and(|cap| self.buffer.len() as u64 > cap) {
                return Err(ResponseError::OversizedHeaderSection);
            }
            self.header_end = self.buffer.len();
            self.framing = Some(body_framing(&self.buffer, self.head_request, status)?);
            if matches!(self.framing, Some(BodyFraming::Chunked)) {
                self.scanner = Some(ChunkScanner::new(self.header_end));
            }
        }
        if self.done || self.framing.is_none() {
            return Ok(());
        }
        let room = self
            .cap
            .unwrap_or(u64::MAX)
            .saturating_sub(self.buffer.len() as u64);
        let remaining = match self.framing {
            Some(BodyFraming::None) => 0,
            Some(BodyFraming::Length(length)) => length
                .saturating_sub((self.buffer.len() - self.header_end) as u64)
                .min(room),
            _ => room,
        };
        let kept = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.buffer.extend_from_slice(&bytes[..kept]);
        let overflow = kept < bytes.len();
        match self.framing {
            Some(BodyFraming::None) => {
                self.buffer.truncate(self.header_end);
                self.done = true;
            }
            Some(BodyFraming::Length(length)) => {
                let end = (self.header_end as u64).saturating_add(length);
                if self.buffer.len() as u64 >= end {
                    self.buffer
                        .truncate(usize::try_from(end).expect("a buffered boundary"));
                    self.done = true;
                } else if self.at_cap() {
                    self.finish(Some(Truncation::Length));
                }
            }
            Some(BodyFraming::Chunked) => {
                if let Some(end) = self
                    .scanner
                    .as_mut()
                    .expect("a chunk scanner")
                    .advance(&self.buffer)?
                {
                    self.buffer.truncate(end);
                    self.done = true;
                } else if overflow {
                    self.finish(Some(Truncation::Length));
                }
            }
            Some(BodyFraming::Close) if overflow => self.finish(Some(Truncation::Length)),
            Some(BodyFraming::Close) | None => {}
        }
        Ok(())
    }

    const fn finish(&mut self, truncated: Option<Truncation>) {
        self.done = true;
        self.truncated = truncated;
    }

    fn at_cap(&self) -> bool {
        self.cap.is_some_and(|cap| self.buffer.len() as u64 >= cap)
    }

    /// Close the capture because the transport ended or ran out of time.
    ///
    /// Pass `None` for a clean EOF, or the reason the transport stopped abnormally. Only a clean
    /// EOF completes a close-delimited response; other unfinished responses are truncated.
    /// Calling this on a capture that is already done changes nothing.
    ///
    /// # Errors
    ///
    /// Fails when no complete response header section was ever received.
    pub fn end(&mut self, reason: Option<Truncation>) -> Result<(), ResponseError> {
        if self.done {
            return Ok(());
        }
        if self.framing.is_none() {
            return Err(ResponseError::IncompleteHeaderSection);
        }
        self.finish(reason.or_else(|| {
            (!matches!(self.framing, Some(BodyFraming::Close))).then_some(Truncation::Disconnect)
        }));
        Ok(())
    }

    /// Take the retained response bytes and the reason they were truncated, if any.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Option<Truncation>) {
        (self.buffer, self.truncated)
    }
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

#[cfg(test)]
mod tests;
