//! Blocking reads of one response from a transport.

use std::io::{ErrorKind, Read};

use crate::Error;
use crate::framing::{ResponseCapture, Truncation};

const READ_LENGTH: usize = 8 * 1024;

enum ReadEvent {
    /// Number of bytes read into the supplied buffer.
    Data(usize),
    /// The connection closed cleanly.
    Closed,
    /// The transport failed after delivering any preceding bytes.
    Disconnected,
    /// The read timed out.
    TimedOut,
}

/// Read once into the transport buffer.
///
/// Rustls reports a close without `close_notify` as `UnexpectedEof`; treat it as a disconnect and
/// retain the bytes received so far.
fn fill(source: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<ReadEvent> {
    loop {
        return match source.read(buffer) {
            Ok(0) => Ok(ReadEvent::Closed),
            Ok(read) => Ok(ReadEvent::Data(read)),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                ) =>
            {
                Ok(ReadEvent::Disconnected)
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(ReadEvent::TimedOut)
            }
            Err(error) => Err(error),
        };
    }
}

/// Read one response verbatim using the incremental parser every backend shares.
pub fn read_response(
    source: &mut impl Read,
    head_request: bool,
    max_length: Option<u64>,
) -> Result<(Vec<u8>, Option<Truncation>), Error> {
    let mut capture = ResponseCapture::new(head_request, max_length);
    let mut bytes = [0; READ_LENGTH];
    while !capture.is_done() {
        match fill(source, &mut bytes)? {
            ReadEvent::Data(read) => capture.push(&bytes[..read])?,
            ReadEvent::Closed => capture.end(None)?,
            ReadEvent::Disconnected => capture.end(Some(Truncation::Disconnect))?,
            ReadEvent::TimedOut => capture.end(Some(Truncation::Time))?,
        }
    }
    Ok(capture.into_parts())
}
