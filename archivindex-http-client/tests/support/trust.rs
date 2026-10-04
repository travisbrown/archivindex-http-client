//! Trust in a test certificate for the clients configured with `rustls`.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;

/// A client configuration whose only root is `certificate`.
pub fn config(certificate: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).expect("a root");

    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("supported protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}
