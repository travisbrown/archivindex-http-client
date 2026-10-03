//! TLS configuration of the clients built on `rustls`: the recorder and the `reqwest` client.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use archivindex_http_client::Client;
use archivindex_http_client::recorder::Recorder;
use archivindex_http_client::reqwest::ReqwestClient;
use http::Uri;

#[path = "support/certificate.rs"]
mod certificate;
#[path = "support/request.rs"]
mod request;
#[path = "support/trust.rs"]
mod trust;

/// Read a request header section and answer it with an empty response.
fn answer(stream: &mut (impl Read + Write)) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("a readable request");
        request.push(byte[0]);
    }
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .expect("a writable response");
    stream.flush().expect("a flushed response");
}

/// These clients speak only HTTP/1.1. A TLS configuration from the caller that also offers `h2`
/// must not let an origin select it, because the exchange would then fail. The caller's own
/// configuration stays as it was.
#[test]
fn a_tls_configuration_that_offers_http2_negotiates_http1() {
    let offered = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let (certificate, mut server_config) =
        certificate::self_signed("localhost", &[&rustls::version::TLS13]);
    server_config.alpn_protocols.clone_from(&offered);
    let server_config = Arc::new(server_config);
    let mut client_config = trust::config(&certificate);
    Arc::make_mut(&mut client_config)
        .alpn_protocols
        .clone_from(&offered);

    let recorder = Recorder::new().tls_config(Arc::clone(&client_config));
    let reqwest = ReqwestClient::new().tls_config(Arc::clone(&client_config));
    assert_eq!(client_config.alpn_protocols, offered);

    for client in [&recorder as &dyn Client, &reqwest] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("a bound address").port();
        let config = Arc::clone(&server_config);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("one connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("a read timeout");
            let connection = rustls::ServerConnection::new(config).expect("a TLS session");
            let mut tls = rustls::StreamOwned::new(connection, stream);
            answer(&mut tls);

            tls.conn.alpn_protocol().map(<[u8]>::to_vec)
        });

        let target: Uri = format!("https://localhost:{port}/")
            .parse()
            .expect("a target");
        let captured = client
            .fetch(request::get(&target))
            .expect("a captured exchange");

        assert_eq!(captured.response_metadata.status, 204);
        assert_eq!(
            server.join().expect("a served request"),
            Some(b"http/1.1".to_vec())
        );
    }
}

/// The default TLS configuration names its crypto provider, so the clients work whatever provider
/// the process has installed. The one installed here supports no cipher suites, which a client
/// that relied on the process default could not use.
///
/// Installing a provider affects the whole process. The other test in this file names a provider
/// in every configuration it builds, so it is unaffected.
#[test]
fn the_default_tls_configuration_ignores_the_process_default_provider() {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites.clear();
    provider
        .install_default()
        .expect("no provider installed before this one");

    let recorder = Recorder::new();
    let reqwest = ReqwestClient::new();

    for client in [&recorder as &dyn Client, &reqwest] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let address = listener.local_addr().expect("a bound address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one connection");
            answer(&mut stream);
        });

        let target: Uri = format!("http://{address}/").parse().expect("a target");
        let captured = client
            .fetch(request::get(&target))
            .expect("a captured exchange");

        assert_eq!(captured.response_metadata.status, 204);
        server.join().expect("a served request");
    }
}
