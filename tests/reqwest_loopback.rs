//! The client contract for the reqwest client, checked against scripted loopback servers.

use std::io::Write as _;
use std::net::TcpListener;
use std::thread;

use archivindex_http_client::reqwest::ReqwestClient as Client;
use archivindex_http_client::{Client as _, Fidelity, Request};
use http::{HeaderMap, HeaderValue, Method};
use rustls::pki_types::CertificateDer;

#[path = "support/certificate.rs"]
mod certificate;
#[path = "support/client_conformance.rs"]
mod client_conformance;
#[path = "support/proxy_conformance.rs"]
mod proxy_conformance;
#[path = "support/request.rs"]
mod request;
#[path = "support/server.rs"]
mod server;
#[path = "support/trust.rs"]
mod trust;

/// `reqwest` does not expose TLS information for a `rustls` connection made through SOCKS.
const PROXIED_TLS_VERSION_IS_REPORTED: bool = false;

fn client() -> Client {
    Client::new()
}

fn trusted_client(certificate: &CertificateDer<'static>) -> Client {
    client().tls_config(trust::config(certificate))
}

/// The response head is rebuilt from parsed parts, so it keeps the fields and their order but not
/// the origin's spelling of them.
#[test]
fn the_response_head_is_reconstructed() {
    let (port, capture) = server::serve(
        b"HTTP/1.1 200 Okey-Dokey\r\nContent-Length: 5\r\nX-MiXeD-CaSe:\t Kept \r\n\r\nhello",
    );

    let captured = server::fetch(&client(), port, "/");
    capture.join().expect("a served request");

    assert_eq!(
        captured.response,
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-mixed-case: Kept\r\n\r\nhello"
    );
    assert_eq!(captured.fidelity, Fidelity::Reconstructed);
    assert_eq!(captured.truncated, None);
}

/// A chunked body stays chunked and keeps its trailers, but its chunks are the pieces `reqwest`
/// delivered, without the origin's chunk extensions. The interim response is dropped.
#[test]
fn a_chunked_body_is_chunked_again_with_its_trailers() {
    let interim = b"HTTP/1.1 103 Early Hints\r\nlink: </style>\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-checksum\r\n\r\n\
        4;ext=a\r\nWiki\r\n5\r\npedia\r\n0;done=yes\r\nx-checksum: abc\r\n\r\n";
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = server::read_request(&mut stream);
        stream.write_all(interim).unwrap();
        stream.write_all(response).unwrap();
        request
    });

    let captured = server::fetch(&client(), port, "/chunked");

    assert_eq!(captured.request, server.join().unwrap());
    assert!(captured.response.starts_with(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-checksum\r\n\r\n"
    ));
    assert!(
        captured
            .response
            .ends_with(b"\r\n0\r\nx-checksum: abc\r\n\r\n")
    );
    assert!(!captured.stored_body().contains(&b';'));
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"Wikipedia");
    assert_eq!(captured.truncated, None);
}

/// `reqwest` appends `accept: */*` to a request without an `accept` field. The stored request has
/// to show it, and a caller's own `accept` must be the only one sent.
#[test]
fn the_stored_request_shows_the_default_accept_field() {
    for (configured, expected) in [
        (None, "accept: */*\r\n"),
        (Some("text/html"), "accept: text/html\r\n"),
    ] {
        let (port, capture) = server::serve(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        let mut headers = HeaderMap::new();
        if let Some(value) = configured {
            headers.insert("accept", HeaderValue::from_static(value));
        }

        let captured = client()
            .fetch(Request {
                headers: &headers,
                ..request::get(&server::target(port, "/"))
            })
            .expect("a captured exchange");

        assert_eq!(captured.request, capture.join().expect("a served request"));
        let request = String::from_utf8(captured.request).unwrap();
        assert_eq!(request.matches("accept:").count(), 1, "{request}");
        assert!(request.contains(expected), "{request}");
    }
}

/// An empty body is still a body, so its length is declared, and the caller's own framing fields
/// never reach the origin.
#[test]
fn request_framing_describes_the_body_that_is_sent() {
    for (body, length) in [
        (b"".as_slice(), "content-length: 0\r\n"),
        (b"four", "content-length: 4\r\n"),
    ] {
        let (port, capture) = server::serve(b"HTTP/1.1 204 No Content\r\n\r\n");
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("99"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));

        let captured = client()
            .fetch(Request {
                method: &Method::POST,
                target: &server::target(port, "/"),
                headers: &headers,
                body: Some(body),
            })
            .expect("a captured exchange");

        assert_eq!(captured.request, capture.join().expect("a served request"));
        let request = String::from_utf8(captured.request).unwrap();
        assert_eq!(request.matches("content-length:").count(), 1, "{request}");
        assert!(request.contains(length), "{request}");
        assert!(!request.contains("transfer-encoding"), "{request}");
    }
}

/// `reqwest` normalizes the target as the URL Standard says before sending it. The stored request
/// names the target that was sent, while `target_uri` remains the one the caller asked for.
#[test]
fn the_stored_request_names_the_normalized_target() {
    let (port, capture) = server::serve(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    let target = server::target(port, "/a/../b?q=1");

    let captured = client()
        .fetch(request::get(&target))
        .expect("a captured exchange");

    assert_eq!(captured.request, capture.join().expect("a served request"));
    assert!(captured.request.starts_with(b"GET /b?q=1 HTTP/1.1\r\n"));
    assert_eq!(captured.target_uri.as_str(), target.to_string());
}
