//! Synchronous entry to the clients that run on Tokio.

use std::io::ErrorKind;
use std::time::Instant;

use http::Uri;

use crate::{CapturedExchange, Error};

/// Check the target and the deadline, then drive one exchange on a runtime of its own.
///
/// The runtime lives on a dedicated thread, so a caller inside an async runtime does not nest
/// `block_on`, and every task of the exchange is disposed of when the exchange ends. `start` runs
/// on that thread, and is given the target as the RFC 3986 URI it was checked to be.
pub fn fetch<F: Future<Output = Result<CapturedExchange, Error>>>(
    target: &Uri,
    deadline: Option<Instant>,
    start: impl FnOnce(fluent_uri::Uri<String>) -> F + Send,
) -> Result<CapturedExchange, Error> {
    if !matches!(target.scheme_str(), Some("http" | "https")) {
        return Err(Error::UnsupportedScheme);
    }
    if target.host().is_none_or(str::is_empty) {
        return Err(Error::MissingHost);
    }
    // `http::Uri` accepts targets that are not URIs. Refuse one before anything is sent.
    let target_uri = fluent_uri::Uri::parse(target.to_string().as_str())?.to_owned();
    if deadline.is_some_and(|end| end <= Instant::now()) {
        return Err(
            std::io::Error::new(ErrorKind::TimedOut, "the fetch deadline has passed").into(),
        );
    }

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let captured = runtime.block_on(start(target_uri));
                // System DNS uses `spawn_blocking`. Waiting for it while the runtime drops would
                // undo a connect or capture timeout; it may finish after the caller returns.
                runtime.shutdown_background();

                captured
            })
            .join()
            .map_err(|_| std::io::Error::other("the capture worker panicked"))?
    })
}
