//! Opt-in HTTP/2 capture against a local TLS server, independent of external sites.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use archivindex_http_client::framing::Truncation;
use archivindex_http_client::wreq::WreqBackend;
use archivindex_http_client::{Backend as _, Fidelity, TlsVersion};
use http::{HeaderMap, Method, Response, StatusCode, Uri, Version};
use tokio_rustls::TlsAcceptor;
use wreq_util::Profile;

#[path = "support/certificate.rs"]
mod certificate;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Finish {
    Complete,
    Trailers,
    Stall,
    Reset,
}

#[derive(Clone, Copy)]
struct Reply {
    status: StatusCode,
    body: &'static [u8],
    finish: Finish,
    before_headers: bool,
    encoded: bool,
}

impl Default for Reply {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            body: b"hello",
            finish: Finish::Complete,
            before_headers: false,
            encoded: false,
        }
    }
}

struct Received {
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Serve one HTTP/2 exchange over TLS 1.3.
fn serve(reply: Reply) -> (Uri, WreqBackend, thread::JoinHandle<Received>) {
    serve_with_version(reply, &rustls::version::TLS13)
}

/// Serve one HTTP/2 exchange, returning the target, a backend that trusts the server and has
/// HTTP/2 enabled, and the request the server received.
fn serve_with_version(
    reply: Reply,
    version: &'static rustls::SupportedProtocolVersion,
) -> (Uri, WreqBackend, thread::JoinHandle<Received>) {
    let (certificate, mut config) = certificate::self_signed("localhost", &[version]);
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let store = wreq::tls::trust::CertStore::builder()
        .add_der_cert(&certificate)
        .build()
        .unwrap();
    let backend = WreqBackend::new(Profile::Chrome136)
        .http2(true)
        .tls_cert_store(store);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let tls = acceptor.accept(socket).await.unwrap();
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                assert_eq!(tls.get_ref().1.protocol_version(), Some(version.version));
                let mut connection = h2::server::Builder::new()
                    .handshake::<_, &'static [u8]>(tls)
                    .await
                    .unwrap();
                let (request, respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(request.version(), Version::HTTP_2);
                let mut ping = connection.ping_pong().unwrap();
                let pings = async {
                    loop {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        if ping.ping(h2::Ping::opaque()).await.is_err() {
                            break;
                        }
                    }
                };
                let mut received = None;
                {
                    let work = answer(request, respond, reply, &mut received);
                    tokio::pin!(work);
                    tokio::select! {
                        () = &mut work => {},
                        () = pings => {},
                        other = connection.accept() => {
                            assert!(other.is_none_or(|request| request.is_err()));
                        },
                    }
                }

                received.expect("a complete request")
            })
    });

    (
        format!("https://localhost:{port}/wp-json?q=1")
            .parse()
            .unwrap(),
        backend,
        server,
    )
}

/// Read the request into `received`, then answer it as `reply` says.
async fn answer(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<&'static [u8]>,
    reply: Reply,
    received: &mut Option<Received>,
) {
    let (parts, mut body) = request.into_parts();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        data.extend_from_slice(&chunk);
    }
    *received = Some(Received {
        headers: parts.headers,
        body: data,
    });
    if reply.before_headers {
        tokio::time::sleep(Duration::from_millis(300)).await;
        return;
    }
    let no_body = parts.method == Method::HEAD || matches!(reply.status.as_u16(), 204 | 304);
    let mut response = Response::builder()
        .status(reply.status)
        .header("set-cookie", "a=1")
        .header("set-cookie", "b=2")
        .header("content-type", "application/octet-stream");
    if reply.encoded {
        response = response.header("content-encoding", "gzip");
    }
    if reply.status != StatusCode::NO_CONTENT {
        response = response.header("content-length", reply.body.len());
    }
    let mut stream = respond
        .send_response(response.body(()).unwrap(), no_body)
        .unwrap();
    if !no_body {
        stream
            .send_data(reply.body, reply.finish == Finish::Complete)
            .unwrap();
        match reply.finish {
            Finish::Complete => {}
            Finish::Trailers => {
                let mut trailers = HeaderMap::new();
                trailers.append("x-checksum", "first".parse().unwrap());
                trailers.append("x-checksum", "second".parse().unwrap());
                stream.send_trailers(trailers).unwrap();
            }
            Finish::Reset => {
                // Let the partial data reach the client before resetting the stream.
                tokio::time::sleep(Duration::from_millis(30)).await;
                stream.send_reset(h2::Reason::CANCEL);
            }
            Finish::Stall => {
                // Hold the stream open until the client's own timeout closes the connection,
                // however long connecting took.
                std::future::pending::<()>().await;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[test]
fn captures_negotiated_http2_with_finalized_request_headers_and_trailers() {
    let (target, backend, server) = serve(Reply {
        finish: Finish::Trailers,
        ..Reply::default()
    });
    let mut headers = HeaderMap::new();
    headers.append("x-duplicate", "one".parse().unwrap());
    headers.append("x-duplicate", "two".parse().unwrap());
    headers.insert("connection", "x-hop".parse().unwrap());
    headers.insert("x-hop", "remove-me".parse().unwrap());

    let captured = backend
        .fetch(&Method::POST, &target, &headers, Some(b"request body"))
        .unwrap();
    let received = server.join().unwrap();

    assert_eq!(received.body, b"request body");
    assert_eq!(captured.fidelity, Fidelity::ReconstructedHttp2);
    assert_eq!(captured.tls_version, Some(TlsVersion::V1_3));
    assert_eq!(captured.truncated, None);
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"hello");
    assert!(
        captured
            .response
            .ends_with(b"0\r\nx-checksum: first\r\nx-checksum: second\r\n\r\n")
    );
    let request = String::from_utf8(captured.request).unwrap();
    assert!(request.starts_with("POST /wp-json?q=1 HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\nrequest body"));
    for (name, value) in &received.headers {
        assert!(
            request.contains(&format!("{}: {}\r\n", name, value.to_str().unwrap())),
            "{name}"
        );
    }
    assert!(!request.contains("x-hop"));
    assert!(!request.contains("connection:"));
    assert!(request.contains("user-agent: Mozilla/5.0"));
}

#[test]
fn reports_the_tls_version_of_an_http2_connection() {
    for (version, expected) in [
        (&rustls::version::TLS12, TlsVersion::V1_2),
        (&rustls::version::TLS13, TlsVersion::V1_3),
    ] {
        let (target, backend, server) = serve_with_version(Reply::default(), version);

        let captured = backend
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();

        assert_eq!(captured.fidelity, Fidelity::ReconstructedHttp2);
        assert_eq!(captured.tls_version, Some(expected));
    }
}

#[test]
fn head_and_bodyless_statuses_preserve_representation_length() {
    for (method, status) in [
        (Method::HEAD, StatusCode::OK),
        (Method::GET, StatusCode::NO_CONTENT),
        (Method::GET, StatusCode::NOT_MODIFIED),
    ] {
        let (target, backend, server) = serve(Reply {
            status,
            ..Reply::default()
        });

        let captured = backend
            .fetch(&method, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();

        assert_eq!(captured.stored_body(), b"");
        assert_eq!(captured.truncated, None);
        if status != StatusCode::NO_CONTENT {
            assert!(String::from_utf8_lossy(&captured.response).contains("content-length: 5\r\n"));
        }
    }
}

#[test]
fn caps_count_reconstructed_bytes_and_distinguish_exact_completion() {
    let (target, backend, server) = serve(Reply::default());
    let complete = backend
        .fetch(&Method::GET, &target, &HeaderMap::new(), None)
        .unwrap();
    server.join().unwrap();

    for (cap, truncated) in [
        (complete.response.len(), None),
        (complete.response.len() - 1, Some(Truncation::Length)),
    ] {
        let (target, backend, server) = serve(Reply::default());

        let captured = backend
            .max_response_length(Some(cap as u64))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();

        assert_eq!(captured.response.len(), cap);
        assert_eq!(captured.truncated, truncated);
    }
}

#[test]
fn stalled_and_reset_streams_retain_truncated_payloads() {
    for (finish, truncation) in [
        (Finish::Stall, Truncation::Time),
        (Finish::Reset, Truncation::Disconnect),
    ] {
        let (target, backend, server) = serve(Reply {
            finish,
            ..Reply::default()
        });

        let captured = backend
            .io_timeout(Some(Duration::from_millis(100)))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .unwrap();
        server.join().unwrap();

        assert_eq!(captured.truncated, Some(truncation));
        assert_eq!(captured.stored_body(), b"5\r\nhello\r\n");
    }
}

#[test]
fn timeout_before_headers_fails() {
    let (target, backend, server) = serve(Reply {
        before_headers: true,
        ..Reply::default()
    });

    assert!(
        backend
            .io_timeout(Some(Duration::from_millis(100)))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .is_err()
    );
    server.join().unwrap();
}

#[test]
fn content_coding_is_preserved_without_decompression() {
    const GZIP: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00";
    let (target, backend, server) = serve(Reply {
        body: GZIP,
        encoded: true,
        ..Reply::default()
    });

    let captured = backend
        .fetch(&Method::GET, &target, &HeaderMap::new(), None)
        .unwrap();
    server.join().unwrap();

    assert_eq!(captured.entity_body().unwrap().as_ref(), GZIP);
    assert!(String::from_utf8_lossy(&captured.response).contains("content-encoding: gzip\r\n"));
}

#[test]
fn response_head_must_fit_the_capture_limit() {
    let (target, backend, server) = serve(Reply::default());

    assert!(
        backend
            .max_response_length(Some(1))
            .fetch(&Method::GET, &target, &HeaderMap::new(), None)
            .is_err()
    );
    server.join().unwrap();
}

/// The deadline also covers connecting and the TLS handshake, so it is generous enough for a loaded
/// machine. The server stalls until the client closes the connection, so it cannot end first.
#[test]
fn absolute_deadline_truncates_an_http2_response() {
    let (target, backend, server) = serve(Reply {
        finish: Finish::Stall,
        ..Reply::default()
    });

    let captured = backend
        .io_timeout(None)
        .fetch_by(
            &Method::GET,
            &target,
            &HeaderMap::new(),
            None,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    server.join().unwrap();

    assert_eq!(captured.truncated, Some(Truncation::Time));
    assert_eq!(captured.stored_body(), b"5\r\nhello\r\n");
}
