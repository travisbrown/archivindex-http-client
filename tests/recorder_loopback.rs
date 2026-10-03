//! The client contract for the recorder, checked against scripted loopback servers.

use archivindex_http_client::recorder::Recorder as Client;
use rustls::pki_types::CertificateDer;

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
#[path = "support/trust.rs"]
mod trust;

const PROXIED_TLS_VERSION_IS_REPORTED: bool = true;

fn client() -> Client {
    Client::new()
}

fn trusted_client(certificate: &CertificateDer<'static>) -> Client {
    client().tls_config(trust::config(certificate))
}
