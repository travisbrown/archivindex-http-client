//! Self-signed TLS identities for local test servers.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

/// A self-signed certificate for `host`, and a server configuration that presents it and accepts
/// only `versions`.
pub fn self_signed(
    host: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> (CertificateDer<'static>, rustls::ServerConfig) {
    let generated =
        rcgen::generate_simple_self_signed(vec![host.to_owned()]).expect("a certificate");
    let certificate = generated.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .expect("supported protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key.into())
    .expect("a server configuration");

    (certificate, config)
}
