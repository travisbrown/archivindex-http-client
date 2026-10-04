//! Blocking reads of one response from a transport.

use std::io::{ErrorKind, Read};

use crate::framing::{ResponseCapture, Truncation};
use crate::{Error, failure};

const READ_LENGTH: usize = 8 * 1024;

/// Read one response verbatim using the incremental parser every client shares.
///
/// Rustls reports a close without `close_notify` as `UnexpectedEof`; treat it as a disconnect and
/// retain the bytes received so far.
pub fn read_response(
    source: &mut impl Read,
    head_request: bool,
    max_length: Option<u64>,
) -> Result<(Vec<u8>, Option<Truncation>), Error> {
    let mut capture = ResponseCapture::new(head_request, max_length);
    let mut bytes = [0; READ_LENGTH];
    while !capture.is_done() {
        match source.read(&mut bytes) {
            Ok(0) => capture.end(None)?,
            Ok(read) => capture.push(&bytes[..read])?,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
                ) =>
            {
                capture.end(Some(Truncation::Disconnect))?;
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                failure::end(&mut capture, Some(Truncation::Time))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(capture.into_parts())
}
