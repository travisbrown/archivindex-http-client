//! The client contract for the wreq client, checked against scripted loopback servers.

use archivindex_http_client::wreq::{WreqClient as Client, parse_profile};
use rustls::pki_types::CertificateDer;
use wreq_util::Profile;

#[path = "support/certificate.rs"]
mod certificate;
#[path = "support/client_conformance.rs"]
mod client_conformance;
#[path = "support/exact_conformance.rs"]
mod exact_conformance;
#[path = "support/proxy_conformance.rs"]
mod proxy_conformance;
#[path = "support/request.rs"]
mod request;
#[path = "support/server.rs"]
mod server;

const PROXIED_TLS_VERSION_IS_REPORTED: bool = true;

const fn client() -> Client {
    Client::new(Profile::Chrome136)
}

fn trusted_client(certificate: &CertificateDer<'static>) -> Client {
    let store = wreq::tls::trust::CertStore::builder()
        .add_der_cert(certificate)
        .build()
        .expect("a root");

    client().tls_cert_store(store)
}

#[test]
fn profiles_are_named_explicitly_and_validated() {
    assert_eq!(parse_profile("chrome_136").unwrap(), Profile::Chrome136);
    assert!(parse_profile("chrome_136 ").is_err());
    assert!(parse_profile("not_a_browser").is_err());
    assert!(parse_profile("").is_err());
}

/// The profile supplies the default request headers, so replacing it changes the stored request.
#[test]
fn the_profile_can_be_replaced() {
    let user_agent = |client: &Client| {
        let (port, server) = server::serve(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        let captured = server::fetch(client, port, "/");
        assert_eq!(captured.request, server.join().unwrap());

        String::from_utf8(captured.request)
            .unwrap()
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("user-agent:"))
            .expect("a user agent")
            .to_owned()
    };

    assert!(user_agent(&client()).contains("Chrome/136"));
    assert!(user_agent(&client().profile(Profile::Firefox136)).contains("Firefox/136"));
}

/// HTTP/2 is opt-in: a client that has not enabled it offers only `http/1.1`, so an origin that
/// prefers `h2` still gets an HTTP/1.1 exchange, stored exactly.
#[test]
fn http2_is_not_negotiated_unless_enabled() {
    use std::io::Write as _;

    use archivindex_http_client::{Client as _, Fidelity};

    let response: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (certificate, mut config) =
        certificate::self_signed("localhost", &[&rustls::version::TLS13]);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let connection = rustls::ServerConnection::new(std::sync::Arc::new(config)).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, stream);
        let request = server::read_request(&mut tls);
        assert_eq!(tls.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
        tls.write_all(response).unwrap();
        tls.conn.send_close_notify();
        tls.flush().unwrap();

        request
    });

    let captured = trusted_client(&certificate)
        .fetch(request::get(
            &format!("https://localhost:{port}/").parse().unwrap(),
        ))
        .unwrap();

    assert_eq!(captured.request, server.join().unwrap());
    assert_eq!(captured.response, response);
    assert_eq!(captured.fidelity, Fidelity::Exact);
}
