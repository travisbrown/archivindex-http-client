//! Scripted loopback origins for the backend tests.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use archivindex_http_client::CapturedExchange;
use http::{HeaderMap, Method, Uri};

use crate::Backend;

/// Read one complete HTTP/1.1 request.
pub fn read_request(stream: &mut impl Read) -> Vec<u8> {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 1024];

    while message_length(&captured).is_none_or(|length| captured.len() < length) {
        let read = stream.read(&mut buffer).expect("readable request");
        assert_ne!(read, 0, "the client hung up mid-request");
        captured.extend_from_slice(&buffer[..read]);
    }

    captured
}

/// Return the complete request length once its header section has arrived.
fn message_length(buffered: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(buffered);
    let headers_end = text.find("\r\n\r\n")? + 4;
    let body_length = text[..headers_end]
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("a numeric length"))
        })
        .unwrap_or(0);

    Some(headers_end + body_length)
}

/// Serve one scripted response and return the received request from the thread.
pub fn serve(response: &'static [u8]) -> (u16, thread::JoinHandle<Vec<u8>>) {
    serve_then(response, Duration::ZERO)
}

/// Serve one response, then wait before closing the connection.
pub fn serve_then(response: &'static [u8], linger: Duration) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("one connection");
        let captured = read_request(&mut stream);
        stream.write_all(response).expect("writable response");
        thread::sleep(linger);

        captured
    });

    (port, handle)
}

/// The URI of `path` on a loopback origin.
pub fn target(port: u16, path: &str) -> Uri {
    format!("http://127.0.0.1:{port}{path}")
        .parse()
        .expect("a target")
}

/// Fetch from a loopback origin without optional headers or a body.
pub fn fetch(backend: &Backend, port: u16, path: &str) -> CapturedExchange {
    use archivindex_http_client::Backend as _;

    backend
        .fetch(&Method::GET, &target(port, path), &HeaderMap::new(), None)
        .expect("a captured exchange")
}
