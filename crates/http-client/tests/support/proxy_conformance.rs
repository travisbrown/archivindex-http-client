//! The SOCKS5 proxy contract every backend satisfies.
//!
//! The proxy serves the destination itself, so reserved hostnames need no DNS.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use archivindex_http_client::{Backend as _, TlsVersion};
use http::{HeaderMap, Method};

use crate::certificate::self_signed;
use crate::server::read_request;
use crate::{PROXIED_TLS_VERSION_IS_REPORTED, backend, trusted_backend};

const HOST: &str = "origin.invalid";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nx-kept: value\r\ncontent-length: 2\r\n\r\nok";

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets can inherit nonblocking mode on macOS.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "proxy connection timed out");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("proxy accept failed: {error}"),
        }
    }
}

fn byte(stream: &mut TcpStream) -> u8 {
    let mut value = [0];
    stream.read_exact(&mut value).unwrap();
    value[0]
}

fn field(stream: &mut TcpStream) -> Vec<u8> {
    let mut value = vec![0; usize::from(byte(stream))];
    stream.read_exact(&mut value).unwrap();
    value
}

fn negotiate(stream: &mut TcpStream, remote_dns: bool, port: u16, auth: bool) {
    assert_eq!(byte(stream), 5);
    let methods = field(stream);
    let method = if auth { 2 } else { 0 };
    assert!(methods.contains(&method));
    stream.write_all(&[5, method]).unwrap();
    if auth {
        assert_eq!(byte(stream), 1);
        assert_eq!(field(stream), b"user@name");
        assert_eq!(field(stream), b"pass:word");
        stream.write_all(&[1, 0]).unwrap();
    }
    let mut header = [0; 3];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header, [5, 1, 0]);
    match byte(stream) {
        3 => {
            let host = field(stream);
            if remote_dns {
                assert_eq!(host, HOST.as_bytes());
            } else {
                // wreq also sends IP literals in domain form with socks5h.
                assert!(
                    std::str::from_utf8(&host)
                        .unwrap()
                        .parse::<IpAddr>()
                        .unwrap()
                        .is_loopback()
                );
            }
        }
        kind @ (1 | 4) => {
            assert!(!remote_dns);
            let ip = if kind == 1 {
                let mut octets = [0; 4];
                stream.read_exact(&mut octets).unwrap();
                IpAddr::from(octets)
            } else {
                let mut octets = [0; 16];
                stream.read_exact(&mut octets).unwrap();
                IpAddr::from(octets)
            };
            assert!(ip.is_loopback());
        }
        kind => panic!("unexpected address kind {kind}"),
    }
    let mut requested_port = [0; 2];
    stream.read_exact(&mut requested_port).unwrap();
    assert_eq!(u16::from_be_bytes(requested_port), port);
    stream.write_all(&[5, 0, 0, 1, 192, 0, 2, 1, 0, 0]).unwrap();
}

fn serve_proxy(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("socks5h://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        responses
            .into_iter()
            .map(|response| {
                let mut stream = accept(&listener);
                negotiate(&mut stream, true, 80, false);
                let request = read_request(&mut stream);
                stream.write_all(&response).unwrap();
                request
            })
            .collect()
    });
    (uri, server)
}

#[test]
fn remote_dns_stores_only_the_http_exchange_and_omits_the_proxy_ip() {
    let (proxy, server) = serve_proxy(vec![RESPONSE.to_vec()]);
    let captured = backend()
        .proxy(Some(&proxy))
        .unwrap()
        .fetch(
            &Method::GET,
            &format!("http://{HOST}/path").parse().unwrap(),
            &HeaderMap::new(),
            None,
        )
        .unwrap();
    assert_eq!(captured.request, server.join().unwrap()[0]);
    assert_eq!(captured.response, RESPONSE);
    assert_eq!(captured.ip_address, None);
}

#[test]
fn local_dns_resolves_hostnames_and_ip_literals_remain_usable() {
    for (scheme, host) in [
        ("socks5", "localhost"),
        ("socks5h", "127.0.0.1"),
        ("socks5h", "[::1]"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("{scheme}://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut stream = accept(&listener);
            negotiate(&mut stream, false, 8080, false);
            let request = read_request(&mut stream);
            stream.write_all(RESPONSE).unwrap();
            request
        });
        let target = format!("http://{host}:8080/local").parse().unwrap();
        let captured = backend()
            .proxy(Some(&proxy))
            .unwrap()
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(captured.request, server.join().unwrap());
    }
}

#[test]
fn authenticated_https_uses_origin_tls_and_captures_plaintext() {
    for (version, expected) in [
        (&rustls::version::TLS12, TlsVersion::V1_2),
        (&rustls::version::TLS13, TlsVersion::V1_3),
    ] {
        let (certificate, tls) = self_signed(HOST, &[version]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!(
            "socks5h://user%40name:pass%3Aword@{}",
            listener.local_addr().unwrap()
        );
        let server = thread::spawn(move || {
            let mut stream = accept(&listener);
            negotiate(&mut stream, true, 443, true);
            let connection = rustls::ServerConnection::new(Arc::new(tls)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let request = read_request(&mut stream);
            stream.write_all(RESPONSE).unwrap();
            stream.flush().unwrap();
            request
        });
        let target = format!("https://{HOST}/secure").parse().unwrap();
        let captured = trusted_backend(&certificate)
            .proxy(Some(&proxy))
            .unwrap()
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(captured.request, server.join().unwrap());
        assert_eq!(captured.response, RESPONSE);
        assert_eq!(
            captured.tls_version,
            PROXIED_TLS_VERSION_IS_REPORTED.then_some(expected)
        );
        assert_eq!(captured.ip_address, None);
    }
}

#[test]
fn rejected_proxy_never_falls_back_to_a_direct_connection() {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("socks5h://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut stream = accept(&listener);
        assert_eq!(byte(&mut stream), 5);
        field(&mut stream);
        stream.write_all(&[5, 255]).unwrap();
    });
    let target = format!("http://{}/", origin.local_addr().unwrap())
        .parse()
        .unwrap();
    assert!(
        backend()
            .proxy(Some(&proxy))
            .unwrap()
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .is_err()
    );
    server.join().unwrap();
    origin.set_nonblocking(true).unwrap();
    assert_eq!(
        origin.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn stalled_proxy_handshakes_obey_connect_timeouts_and_capture_deadlines() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("socks5h://{}", listener.local_addr().unwrap());
    let target = format!("http://{HOST}/").parse().unwrap();
    let backend = backend()
        .proxy(Some(&proxy))
        .unwrap()
        .connect_timeout(Some(Duration::from_millis(100)))
        .io_timeout(Some(Duration::from_millis(100)));
    let start = Instant::now();
    assert!(
        backend
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    let start = Instant::now();
    assert!(
        backend
            .connect_timeout(None)
            .io_timeout(None)
            .fetch_by(
                &Method::GET,
                &target,
                &HeaderMap::new(),
                None,
                start + Duration::from_millis(100)
            )
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn invalid_proxy_uri_fails_before_fetching() {
    for proxy in [
        "socks5h://127.0.0.1:invalid",
        "http://localhost:1080",
        "socks4://localhost:1080",
        "socks5h://localhost/path",
        "socks5h://localhost?query",
        "socks5h://user@localhost",
    ] {
        assert!(backend().proxy(Some(proxy)).is_err());
    }
}
