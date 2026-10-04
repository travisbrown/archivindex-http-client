//! The contract of the clients that store HTTP/1 messages exactly.
//!
//! These responses use spellings that reconstruction would lose: mixed-case field names,
//! non-canonical reason phrases, unusual whitespace, chunk extensions, and interim responses.

use std::io::Write;
use std::net::TcpListener;
use std::thread;

use archivindex_http_client::{Client as _, Fidelity, Request};
use http::{HeaderMap, HeaderValue};

use crate::client;
use crate::request::get;
use crate::server::{fetch, read_request, serve, target};

#[test]
fn stores_the_request_and_response_bytes_exactly() {
    let response: &[u8] =
        b"HTTP/1.1 200 Okey-Dokey\r\nContent-Length: 5\r\nX-MiXeD-CaSe: Kept\r\n\r\nhello";
    let (port, capture) = serve(response);
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("client-test/0.0"));

    let captured = client()
        .fetch(Request {
            headers: &headers,
            ..get(&target(port, "/path?q=1"))
        })
        .expect("a captured exchange");

    assert_eq!(captured.request, capture.join().expect("a served request"));
    assert_eq!(captured.response, response);
    assert_eq!(captured.fidelity, Fidelity::Exact);
    assert_eq!(captured.truncated, None);
}

#[test]
fn stores_a_chunked_response_verbatim() {
    let response: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n\
        4;ext=a\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: abc\r\n\r\n";
    let (port, capture) = serve(response);

    let captured = fetch(&client(), port, "/chunked");
    capture.join().expect("a served request");

    assert_eq!(captured.response, response);
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"Wikipedia");
    assert_eq!(captured.truncated, None);
}

/// The interim response is the only thing dropped. The final response is stored as sent even when
/// it arrives one byte at a time, so that no read boundary falls where the parser expects one.
#[test]
fn preserves_duplicate_headers_whitespace_and_fragmented_chunks_after_an_interim_response() {
    let interim = b"HTTP/1.1 103 Hints\r\nLink: </style>\r\n\r\n";
    let response = b"HTTP/1.1 200 Very Fine\r\nX-MiXeD:\t kept \t\r\nX-MiXeD: second\r\n\
        Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n\
        3;foo=bar\r\na\0b\r\n2\r\ncd\r\n0;done=yes\r\nX-End: yes\r\n\r\n";
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        stream.write_all(interim).unwrap();
        for byte in response {
            stream.write_all(&[*byte]).unwrap();
        }
        request
    });

    let captured = fetch(&client(), port, "/fragmented");

    assert_eq!(captured.request, server.join().unwrap());
    assert_eq!(captured.response, response);
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"a\0bcd");
    assert_eq!(captured.truncated, None);
}
