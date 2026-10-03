//! The end of a chunked body, found as its bytes arrive.

use super::{ResponseError, find_crlf};

/// Incrementally locates the end of a chunked body.
///
/// [`advance`](Self::advance) returns the offset after the trailer section once the body is
/// complete. It never changes the buffered bytes.
pub struct ChunkScanner {
    /// The offset of the next unexamined byte.
    offset: usize,
    /// First byte that can still begin a CRLF in the current incomplete line.
    line_search: usize,
    stage: ChunkStage,
}

enum ChunkStage {
    /// A chunk-size line.
    Size,
    /// Chunk data and its terminating CRLF.
    Data(u64),
    /// The trailer section, ending at an empty line.
    Trailers,
}

impl ChunkScanner {
    /// Start at the first chunk-size line.
    pub const fn new(offset: usize) -> Self {
        Self {
            offset,
            line_search: offset,
            stage: ChunkStage::Size,
        }
    }

    /// Search only new bytes, retaining one byte for a CRLF split across reads.
    fn line_end(&mut self, buffer: &[u8]) -> Option<usize> {
        let start = self.line_search.max(self.offset);
        if let Some(relative) = find_crlf(&buffer[start..]) {
            let end = start + relative;
            self.line_search = end + 2;
            Some(end)
        } else {
            self.line_search = buffer.len().saturating_sub(1);
            None
        }
    }

    /// Scan available bytes and return the message end when complete.
    pub fn advance(&mut self, buffer: &[u8]) -> Result<Option<usize>, ResponseError> {
        loop {
            match self.stage {
                ChunkStage::Size => {
                    let Some(line_end) = self.line_end(buffer) else {
                        return Ok(None);
                    };
                    let line = &buffer[self.offset..line_end];
                    let size_text = line
                        .split(|&byte| byte == b';')
                        .next()
                        .unwrap_or(line)
                        .trim_ascii();
                    let size = parse_chunk_size(size_text)?;
                    self.offset = line_end + 2;
                    self.stage = if size == 0 {
                        ChunkStage::Trailers
                    } else {
                        ChunkStage::Data(size)
                    };
                }
                ChunkStage::Data(remaining) => {
                    let held = (buffer.len() - self.offset) as u64;
                    if held < remaining + 2 {
                        return Ok(None);
                    }
                    let data_end = self.offset
                        + usize::try_from(remaining)
                            .expect("invariant violation: buffered chunk data overflowed usize");
                    if &buffer[data_end..data_end + 2] != b"\r\n" {
                        return Err(ResponseError::UnterminatedChunk);
                    }
                    self.offset = data_end + 2;
                    self.stage = ChunkStage::Size;
                }
                ChunkStage::Trailers => {
                    let Some(line_end) = self.line_end(buffer) else {
                        return Ok(None);
                    };
                    let empty = line_end == self.offset;
                    self.offset = line_end + 2;
                    if empty {
                        return Ok(Some(self.offset));
                    }
                }
            }
        }
    }
}

/// Parse a chunk size while reserving room for its trailing CRLF.
fn parse_chunk_size(text: &[u8]) -> Result<u64, ResponseError> {
    let malformed =
        || ResponseError::MalformedChunkSize(String::from_utf8_lossy(text).into_owned());

    if text.is_empty() {
        return Err(malformed());
    }

    let mut size = 0u64;
    for &byte in text {
        let digit = char::from(byte).to_digit(16).ok_or_else(malformed)?;
        size = size
            .checked_mul(16)
            .and_then(|size| size.checked_add(u64::from(digit)))
            .filter(|size| *size <= u64::MAX - 2)
            .ok_or_else(malformed)?;
    }

    Ok(size)
}
