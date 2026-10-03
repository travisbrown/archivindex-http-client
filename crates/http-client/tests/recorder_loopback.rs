//! The backend contract for the recorder, checked against scripted loopback servers.

use archivindex_http_client::recorder::Recorder as Backend;
use rustls::pki_types::CertificateDer;

#[path = "support/backend_conformance.rs"]
mod backend_conformance;
#[path = "support/certificate.rs"]
mod certificate;
#[path = "support/exact_conformance.rs"]
mod exact_conformance;
#[path = "support/proxy_conformance.rs"]
mod proxy_conformance;
#[path = "support/server.rs"]
mod server;
#[path = "support/trust.rs"]
mod trust;

const PROXIED_TLS_VERSION_IS_REPORTED: bool = true;

fn backend() -> Backend {
    Backend::new()
}

fn trusted_backend(certificate: &CertificateDer<'static>) -> Backend {
    backend().tls_config(trust::config(certificate))
}
