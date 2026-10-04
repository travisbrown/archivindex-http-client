//! Message framing shared by every capture client.
//!
//! [`ResponseCapture`] turns received bytes into the stored response of one exchange. It owns the
//! rules that decide where a response ends, when it is complete, and why it was cut short. Clients
//! feed it either observed HTTP/1 bytes or a reconstructed message.

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

/// Incremental capture of one stored response, shared by every client.
///
/// Feed it transport reads with [`push`](Self::push) and close it with [`end`](Self::end).
/// Each header section is limited to 64 KiB. Interim responses are discarded; the final header
/// section and body also count toward the configured response limit.
pub struct ResponseCapture {
    buffer: Vec<u8>,
    head_request: bool,
    cap: Option<u64>,
    state: State,
}

enum State {
    Head,
    Length(u64),
    Chunked(ChunkScanner),
    Close,
    Done(Option<Truncation>),
}

impl ResponseCapture {
    /// Start a capture.
    ///
    /// Set `head_request` when the request method was `HEAD`, so that a declared body length is
    /// not awaited. `cap` bounds stored bytes, including the final header section.
    #[must_use]
    pub const fn new(head_request: bool, cap: Option<u64>) -> Self {
        Self {
            buffer: Vec::new(),
            head_request,
            cap,
            state: State::Head,
        }
    }

    /// Whether the response is complete, capped, or truncated, so no further bytes are wanted.
    ///
    /// A client should stop reading and dispose of its connection once this is true.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self.state, State::Done(_))
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
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<(), ResponseError> {
        while matches!(self.state, State::Head) && !bytes.is_empty() {
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
            self.state = match body_framing(&self.buffer, self.head_request, status)? {
                BodyFraming::None | BodyFraming::Length(0) => State::Done(None),
                BodyFraming::Length(length) => State::Length(length),
                BodyFraming::Chunked => State::Chunked(ChunkScanner::new(self.buffer.len())),
                BodyFraming::Close => State::Close,
            };
        }
        if matches!(self.state, State::Head | State::Done(_)) {
            return Ok(());
        }
        let room = self
            .cap
            .unwrap_or(u64::MAX)
            .saturating_sub(self.buffer.len() as u64);
        let remaining = match self.state {
            State::Length(length) => length.min(room),
            _ => room,
        };
        let kept = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.buffer.extend_from_slice(&bytes[..kept]);
        let overflow = kept < bytes.len();
        match &mut self.state {
            State::Length(remaining) => {
                *remaining -= kept as u64;
                if *remaining == 0 {
                    self.state = State::Done(None);
                } else if kept as u64 == room {
                    self.state = State::Done(Some(Truncation::Length));
                }
            }
            State::Chunked(scanner) => {
                if let Some(end) = scanner.advance(&self.buffer)? {
                    self.buffer.truncate(end);
                    self.state = State::Done(None);
                } else if overflow {
                    self.state = State::Done(Some(Truncation::Length));
                }
            }
            State::Close if overflow => self.state = State::Done(Some(Truncation::Length)),
            State::Head | State::Close | State::Done(_) => {}
        }
        Ok(())
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
        self.state = match self.state {
            State::Head => return Err(ResponseError::IncompleteHeaderSection),
            State::Done(_) => return Ok(()),
            State::Close => State::Done(reason),
            State::Length(_) | State::Chunked(_) => {
                State::Done(Some(reason.unwrap_or(Truncation::Disconnect)))
            }
        };
        Ok(())
    }

    /// Take the retained response bytes and the reason they were truncated, if any.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Option<Truncation>) {
        let truncated = match self.state {
            State::Done(reason) => reason,
            _ => None,
        };
        (self.buffer, truncated)
    }
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

#[cfg(test)]
mod tests;
