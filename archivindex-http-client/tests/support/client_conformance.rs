//! The contract every client satisfies, whether it stores exact or reconstructed messages.
//!
//! Scripted responses are written the way a reconstructing client stores them, with lowercase
//! field names, canonical reason phrases, and one space after each colon. The stored response can
//! therefore be compared with the scripted bytes for every client.

use std::io::{ErrorKind, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use archivindex_http_client::framing::Truncation;
use archivindex_http_client::{Client as _, Error, HttpProtocol, Request, TlsVersion};
use http::{HeaderMap, HeaderValue, Method, Uri};

use crate::certificate::self_signed;
use crate::request::get;
use crate::server::{fetch, read_request, serve, serve_then, target};
use crate::{client, trusted_client};

#[test]
fn stores_the_request_the_origin_received_and_the_response_it_sent() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-kept: value\r\n\r\nhello";
    let (port, capture) = serve(response);

    let target = target(port, "/path?q=1");
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("client-test/0.0"));

    let captured = client()
        .fetch(Request {
            headers: &headers,
            ..get(&target)
        })
        .expect("a captured exchange");
    let received = capture.join().expect("a served request");

    assert_eq!(captured.request, received);
    let request = String::from_utf8_lossy(&captured.request).to_ascii_lowercase();
    assert!(
        request.starts_with("get /path?q=1 http/1.1\r\n"),
        "{request}"
    );
    assert!(
        request.contains(&format!("host: 127.0.0.1:{port}\r\n")),
        "{request}"
    );
    assert!(
        request.contains("user-agent: client-test/0.0\r\n"),
        "{request}"
    );
    assert!(request.contains("connection: close\r\n"), "{request}");

    assert_eq!(captured.response, response);
    assert_eq!(captured.response_metadata.status, 200);
    assert_eq!(captured.stored_body(), b"hello");
    assert_eq!(captured.ip_address.unwrap().to_string(), "127.0.0.1");
    assert_eq!(captured.target_uri.as_str(), target.to_string());
    assert_eq!(captured.http_protocol, HttpProtocol::Http1);
    assert_eq!(captured.tls_version, None);
    assert_eq!(captured.truncated, None);
}

/// `connection: close` is only a default, so a caller's own `connection` header is sent as given.
#[test]
fn keeps_a_configured_connection_header() {
    let (port, capture) = serve(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("keep-alive"));

    let captured = client()
        .fetch(Request {
            headers: &headers,
            ..get(&target(port, "/"))
        })
        .expect("a captured exchange");

    assert_eq!(captured.request, capture.join().expect("a served request"));
    let request = String::from_utf8_lossy(&captured.request).to_ascii_lowercase();
    assert!(request.contains("connection: keep-alive\r\n"), "{request}");
    assert!(!request.contains("connection: close"), "{request}");
}

/// The stored body keeps its chunked framing, and the entity-body is recovered from it. Whether
/// the stored chunks are the origin's depends on the client's fidelity.
#[test]
fn stores_a_chunked_response_with_its_framing() {
    let head: &[u8] = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
    let (port, capture) = serve(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
        4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
    );

    let captured = fetch(&client(), port, "/chunked");
    capture.join().expect("a served request");

    assert!(captured.response.starts_with(head));
    assert!(captured.response.ends_with(b"\r\n0\r\n\r\n"));
    assert_eq!(captured.entity_body().unwrap().as_ref(), b"Wikipedia");
    assert_eq!(captured.truncated, None);
}

/// A chunked response that ends before the empty line of its trailer section has no entity-body,
/// even when every chunk arrived. The clients that decode the body themselves never deliver its
/// last chunk in that case, so accepting it would give a different answer for each client.
#[test]
fn a_truncated_chunked_response_has_no_entity_body() {
    for response in [
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n",
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n",
    ] {
        let (port, capture) = serve(response);

        let captured = fetch(&client(), port, "/cut");
        capture.join().expect("a served request");

        assert_eq!(captured.truncated, Some(Truncation::Disconnect));
        assert_eq!(
            captured.entity_body(),
            Err(archivindex_http_client::body::Error::IncompleteChunkedBody),
            "{:?}",
            String::from_utf8_lossy(response)
        );
    }
}

/// The response to a `HEAD` request, and a `204` or `304` response, has no body. Its entity-body
/// is empty even when its header section declares the chunked framing that another response to
/// the same request would have.
#[test]
fn a_response_without_a_body_has_an_empty_entity_body() {
    let cases: [(Method, &[u8]); 3] = [
        (
            Method::HEAD,
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
        ),
        (
            Method::GET,
            b"HTTP/1.1 204 No Content\r\ntransfer-encoding: chunked\r\n\r\n",
        ),
        (
            Method::GET,
            b"HTTP/1.1 304 Not Modified\r\ntransfer-encoding: chunked\r\n\r\n",
        ),
    ];

    for (method, response) in cases {
        let (port, capture) = serve(response);

        let captured = client()
            .fetch(Request {
                method: &method,
                ..get(&target(port, "/"))
            })
            .expect("a captured exchange");
        capture.join().expect("a served request");

        assert_eq!(captured.response, response);
        assert_eq!(captured.truncated, None);
        assert_eq!(captured.entity_body().unwrap().as_ref(), b"");
    }
}

#[test]
fn stores_a_close_delimited_response_to_the_close() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\nx-no-framing: declared\r\n\r\nthe close ends this";
    let (port, capture) = serve(response);

    let captured = fetch(&client(), port, "/unframed");
    capture.join().expect("a served request");

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, None);
}

/// Content coding belongs to the entity-body, so the stored response keeps it and the stored
/// request is still the one the origin received. These tests build `reqwest` with its decoders,
/// which would otherwise ask for a coding the caller did not and decode the response.
#[test]
fn stores_a_content_coded_response_as_the_origin_sent_it() {
    let responses: [&[u8]; 4] = [
        b"HTTP/1.1 200 OK\r\ncontent-encoding: br\r\ncontent-length: 7\r\n\r\nencoded",
        b"HTTP/1.1 200 OK\r\ncontent-encoding: deflate\r\ncontent-length: 7\r\n\r\nencoded",
        b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 7\r\n\r\nencoded",
        b"HTTP/1.1 200 OK\r\ncontent-encoding: zstd\r\ncontent-length: 7\r\n\r\nencoded",
    ];

    for response in responses {
        let (port, capture) = serve(response);

        let captured = fetch(&client(), port, "/coded");

        assert_eq!(captured.request, capture.join().expect("a served request"));
        assert_eq!(captured.response, response);
        assert_eq!(captured.entity_body().unwrap().as_ref(), b"encoded");
        assert_eq!(captured.truncated, None);
    }
}

#[test]
fn stores_a_head_response_through_its_header_section() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n";
    let (port, capture) = serve(response);

    let captured = client()
        .fetch(Request {
            method: &Method::HEAD,
            target: &target(port, "/"),
            headers: &HeaderMap::new(),
            body: None,
        })
        .expect("a captured exchange");
    capture.join().expect("a served request");

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, None);
    assert!(captured.request.starts_with(b"HEAD / HTTP/1.1\r\n"));
}

#[test]
fn frames_and_stores_a_request_body() {
    let response: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    let (port, capture) = serve(response);

    let captured = client()
        .fetch(Request {
            method: &Method::POST,
            target: &target(port, "/submit"),
            headers: &HeaderMap::new(),
            body: Some(b"the request body"),
        })
        .expect("a captured exchange");
    let received = capture.join().expect("a served request");

    assert_eq!(captured.request, received);
    let request = String::from_utf8_lossy(&captured.request).to_ascii_lowercase();
    assert!(request.contains("content-length: 16\r\n"), "{request}");
    assert!(request.ends_with("\r\n\r\nthe request body"), "{request}");
    assert_eq!(captured.response, response);
}

/// Credentials reach the origin only in an `authorization` header from the caller. Userinfo in
/// the target is not sent in any form, where `reqwest` and `wreq` would turn it into `Basic`
/// credentials by themselves. `target_uri` remains the URI the caller asked for.
#[test]
fn sends_credentials_only_from_an_authorization_header() {
    for explicit in [None, Some("Bearer token")] {
        let (port, capture) = serve(b"HTTP/1.1 204 No Content\r\n\r\n");
        let target: Uri = format!("http://user:p%40ss@127.0.0.1:{port}/")
            .parse()
            .expect("a target");
        let headers = explicit
            .map(|value| (http::header::AUTHORIZATION, HeaderValue::from_static(value)))
            .into_iter()
            .collect::<HeaderMap>();

        let captured = client()
            .fetch(Request {
                headers: &headers,
                ..get(&target)
            })
            .expect("a captured exchange");

        assert_eq!(captured.request, capture.join().expect("a served request"));
        let request = String::from_utf8_lossy(&captured.request).to_ascii_lowercase();
        assert_eq!(
            request.matches("authorization:").count(),
            usize::from(explicit.is_some()),
            "{request}"
        );
        assert_eq!(
            request.matches("authorization: bearer token\r\n").count(),
            usize::from(explicit.is_some()),
            "{request}"
        );
        assert!(
            request.contains(&format!("host: 127.0.0.1:{port}\r\n")),
            "{request}"
        );
        assert_eq!(captured.target_uri.as_str(), target.to_string());
    }
}

/// The body given to a fetch frames the request, so the caller's own framing headers never reach
/// the origin. Without a body they would declare one that is not sent, and the origin would wait
/// for it.
#[test]
fn replaces_the_framing_headers_of_the_caller() {
    for (method, body, lengths) in [
        (Method::GET, None, 0),
        (Method::POST, Some(b"four".as_slice()), 1),
    ] {
        let (port, capture) = serve(b"HTTP/1.1 204 No Content\r\n\r\n");
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("99"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));

        let captured = client()
            .fetch(Request {
                method: &method,
                target: &target(port, "/"),
                headers: &headers,
                body,
            })
            .expect("a captured exchange");

        assert_eq!(captured.request, capture.join().expect("a served request"));
        let request = String::from_utf8_lossy(&captured.request).to_ascii_lowercase();
        assert_eq!(
            request.matches("content-length:").count(),
            lengths,
            "{request}"
        );
        assert_eq!(
            request.matches("content-length: 4\r\n").count(),
            lengths,
            "{request}"
        );
        assert!(!request.contains("transfer-encoding"), "{request}");
    }
}

#[test]
fn the_length_bound_truncates_the_response() {
    let response: &[u8] =
        b"HTTP/1.1 200 OK\r\ncontent-length: 26\r\n\r\nabcdefghijklmnopqrstuvwxyz";
    let (port, capture) = serve(response);

    let captured = fetch(&client().max_response_length(Some(45)), port, "/truncated");
    capture.join().expect("a served request");

    assert_eq!(captured.response, &response[..45]);
    assert_eq!(captured.truncated, Some(Truncation::Length));
    assert_eq!(captured.stored_body(), b"abcdef");
}

#[test]
fn a_read_timeout_inside_the_body_truncates_for_time() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial";
    let (port, capture) = serve_then(response, Duration::from_millis(500));

    let captured = fetch(
        &client().io_timeout(Some(Duration::from_millis(100))),
        port,
        "/slow",
    );

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, Some(Truncation::Time));
    capture.join().expect("a served request");
}

#[test]
fn a_deadline_inside_the_body_truncates_for_time() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("one connection");
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n")
            .expect("writable head");
        // A byte within every read timeout, until the client hangs up.
        while stream.write_all(b"x").is_ok() {
            thread::sleep(Duration::from_millis(20));
        }
    });

    let captured = client()
        .io_timeout(Some(Duration::from_secs(5)))
        .fetch_by(
            get(&target(port, "/trickle")),
            Instant::now() + Duration::from_millis(200),
        )
        .expect("a captured exchange");

    assert_eq!(captured.truncated, Some(Truncation::Time));
    assert!(
        captured.fetch_time < Duration::from_secs(5),
        "{:?}",
        captured.fetch_time
    );
    server.join().expect("a served request");
}

#[test]
fn a_passed_deadline_fails_before_connecting() {
    let target: Uri = "http://127.0.0.1:9/".parse().expect("a target");

    let result = client().fetch_by(get(&target), Instant::now());

    assert!(matches!(
        result,
        Err(Error::Io(error)) if error.kind() == ErrorKind::TimedOut
    ));
}

/// A response header section that does not arrive in time is a timed-out I/O operation, whether
/// none or part of it arrived, and whether the I/O timeout or the deadline passed. The error for an
/// incomplete header section would say that the connection ended, which it has not.
#[test]
fn a_timeout_before_the_header_section_is_a_timed_out_operation() {
    for response in [b"".as_slice(), b"HTTP/1.1 200"] {
        for by_deadline in [false, true] {
            let (port, server) = serve_then(response, Duration::from_millis(700));
            let target = target(port, "/");
            let wait = Duration::from_millis(200);

            let result = if by_deadline {
                client().fetch_by(get(&target), Instant::now() + wait)
            } else {
                client().io_timeout(Some(wait)).fetch(get(&target))
            };

            assert!(
                matches!(&result, Err(Error::Io(error)) if error.kind() == ErrorKind::TimedOut),
                "{result:?}"
            );
            server.join().expect("a served request");
        }
    }
}

/// A refused connection keeps its I/O error kind, so a caller can tell it from other failures.
#[test]
fn a_refused_connection_keeps_its_error_kind() {
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port();

    let result = client().fetch(get(&target(port, "/")));

    assert!(
        matches!(&result, Err(Error::Io(error)) if error.kind() == ErrorKind::ConnectionRefused),
        "{result:?}"
    );
}

#[test]
fn a_non_http_scheme_is_refused() {
    let target: Uri = "ftp://example.com/".parse().expect("a target");
    let result = client().fetch(get(&target));

    assert!(matches!(result, Err(Error::UnsupportedScheme)));
}

/// `http::Uri` accepts targets that RFC 3986 does not, and an exchange cannot be stored for one.
/// The fetch must fail before the request is sent, not after the origin has acted on it.
#[test]
fn a_target_that_is_not_a_uri_fails_before_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    listener
        .set_nonblocking(true)
        .expect("a nonblocking listener");
    let port = listener.local_addr().expect("a bound address").port();

    let result = client().fetch(Request {
        method: &Method::POST,
        target: &target(port, "/a{b}|c"),
        headers: &HeaderMap::new(),
        body: Some(b"an effect"),
    });

    assert!(matches!(result, Err(Error::TargetUri(_))));
    assert_eq!(
        listener.accept().expect_err("no connection").kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn stores_the_messages_inside_tls_and_reports_its_version() {
    let response: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\nx-secure: yes\r\n\r\nsecrets";

    for (version, expected) in [
        (&rustls::version::TLS12, TlsVersion::V1_2),
        (&rustls::version::TLS13, TlsVersion::V1_3),
    ] {
        let (certificate, config) = self_signed("localhost", &[version]);
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("a bound address").port();
        let capture = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("one connection");
            let connection =
                rustls::ServerConnection::new(Arc::new(config)).expect("a TLS session");
            let mut tls = rustls::StreamOwned::new(connection, stream);
            let captured = read_request(&mut tls);
            tls.write_all(response).expect("writable response");
            tls.conn.send_close_notify();
            tls.flush().expect("a flushed close");

            captured
        });

        let target: Uri = format!("https://localhost:{port}/tls")
            .parse()
            .expect("a target");
        let captured = trusted_client(&certificate)
            .fetch(get(&target))
            .expect("a captured exchange");
        let received = capture.join().expect("a served request");

        assert_eq!(captured.request, received);
        assert_eq!(captured.response, response);
        assert_eq!(captured.tls_version, Some(expected));
        assert!(
            String::from_utf8_lossy(&captured.request)
                .to_ascii_lowercase()
                .contains(&format!("host: localhost:{port}\r\n"))
        );
    }
}

/// A private root is trusted only when the caller configures it, so a certificate that no trusted
/// root signed fails the fetch. This guards against a client that would skip verification.
#[test]
fn an_untrusted_certificate_fails() {
    let (_, config) = self_signed("localhost", &[&rustls::version::TLS13]);
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("a bound address").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("one connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a read timeout");
        let mut connection =
            rustls::ServerConnection::new(Arc::new(config)).expect("a TLS session");

        // The handshake ends with the alert or the close that the client answers with.
        while connection.is_handshaking() {
            if connection.complete_io(&mut stream).is_err() {
                return false;
            }
        }

        true
    });

    let target: Uri = format!("https://localhost:{port}/untrusted")
        .parse()
        .expect("a target");
    let result = client().fetch(get(&target));

    assert!(result.is_err(), "{result:?}");
    assert!(!server.join().expect("a served connection"));
}

#[test]
fn keeps_what_arrived_before_a_disconnect_after_the_head() {
    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort";
    let (port, server) = serve(response);

    let captured = fetch(&client(), port, "/disconnect");

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, Some(Truncation::Disconnect));
    server.join().unwrap();
}

#[test]
fn incomplete_and_oversized_heads_fail() {
    for (response, cap) in [
        (b"HTTP/1.1 200 OK\r\ncontent-".as_slice(), None),
        (
            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".as_slice(),
            Some(10),
        ),
    ] {
        let (port, server) = serve(response);

        let result = client()
            .max_response_length(cap)
            .fetch(get(&target(port, "/")));

        assert!(result.is_err());
        server.join().unwrap();
    }
}

/// Chunk framing that cannot be parsed is a failure, not a truncated response, because nothing
/// after it can be attributed to the message.
#[test]
fn malformed_chunk_framing_fails() {
    let (port, server) =
        serve(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nnot-hex\r\nbody\r\n0\r\n\r\n");

    let result = client().fetch(get(&target(port, "/")));

    assert!(result.is_err());
    server.join().unwrap();
}

#[test]
fn a_limit_equal_to_the_response_length_does_not_truncate() {
    for response in [
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".as_slice(),
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".as_slice(),
        // The trailer section is part of the stored message, so it counts towards the limit.
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nx-sum: 2\r\n\r\n"
            .as_slice(),
        b"HTTP/1.1 200 OK\r\n\r\nok".as_slice(),
    ] {
        let (port, server) = serve(response);

        let captured = fetch(
            &client().max_response_length(Some(response.len() as u64)),
            port,
            "/cap",
        );

        assert_eq!(captured.response, response);
        assert_eq!(captured.truncated, None);
        server.join().unwrap();
    }
}

#[test]
fn concurrent_captures_keep_their_own_bytes() {
    let workers: Vec<_> = (0..8)
        .map(|index| {
            thread::spawn(move || {
                let (port, server) = serve(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
                let captured = fetch(&client(), port, &format!("/request-{index}"));

                assert_eq!(captured.request, server.join().unwrap());
                assert!(
                    captured
                        .request
                        .starts_with(format!("GET /request-{index} HTTP/1.1\r\n").as_bytes())
                );
            })
        })
        .collect();

    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn a_known_length_limit_does_not_wait_for_the_rest_of_the_body() {
    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 1000000\r\n\r\nprefix";
    let (port, server) = serve_then(response, Duration::from_millis(500));

    let captured = fetch(
        &client().max_response_length(Some(response.len() as u64)),
        port,
        "/limit",
    );

    assert_eq!(captured.response, response);
    assert_eq!(captured.truncated, Some(Truncation::Length));
    assert!(captured.fetch_time < Duration::from_millis(400));
    server.join().unwrap();
}

/// One fetch is one exchange. A redirect or a retryable status is returned as the response, and a
/// failed exchange is not retried, so the origin sees exactly one connection each time.
#[test]
fn no_hidden_redirects_or_retries() {
    for status in ["302 Found", "503 Service Unavailable", "disconnect"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let serving = listener.try_clone().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = serving.accept().unwrap();
            let request = read_request(&mut stream);
            if status != "disconnect" {
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nlocation: /next\r\ncontent-length: 0\r\n\r\n"
                )
                .unwrap();
            }
            request
        });

        let result = client()
            .io_timeout(Some(Duration::from_millis(200)))
            .fetch(get(&target(port, "/first")));
        let request = server.join().unwrap();

        if status == "disconnect" {
            assert!(result.is_err());
        } else {
            let captured = result.unwrap();
            assert_eq!(captured.request, request);
            assert!(captured.response.starts_with(b"HTTP/1.1 "));
            assert_eq!(&captured.response[9..12], &status.as_bytes()[..3]);
        }
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock));
    }
}

/// Clients are synchronous, and callers on an async runtime call them without `spawn_blocking`
/// only if a fetch never blocks on that runtime from inside it.
#[test]
fn a_fetch_works_inside_a_tokio_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    runtime.block_on(async {
        let (port, server) = serve(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        let captured = fetch(&client(), port, "/nested");

        assert_eq!(captured.request, server.join().unwrap());
    });
}

/// The response cap includes generated or observed chunk framing and trailers.
#[test]
fn chunked_limits_include_trailers_and_preserve_exact_completion() {
    let head = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-end\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-end\r\n\r\n1\r\nx\r\n0\r\nx-end: yes\r\n\r\n";
    for limit in head.len()..=response.len() {
        let (port, server) = serve(response);
        let captured = fetch(
            &client().max_response_length(Some(limit as u64)),
            port,
            "/chunk-cap",
        );
        server.join().unwrap();
        assert_eq!(captured.response, response[..limit]);
        if limit == response.len() {
            assert_eq!(captured.truncated, None);
            assert_eq!(captured.entity_body().unwrap().as_ref(), b"x");
        } else {
            assert_eq!(captured.truncated, Some(Truncation::Length));
            assert_eq!(
                captured.entity_body(),
                Err(archivindex_http_client::body::Error::IncompleteChunkedBody)
            );
        }
    }
}
