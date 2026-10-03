//! The TLS configuration that the clients built on `rustls` start from.

use std::sync::Arc;

/// Offer only `http/1.1` in the ALPN extension of `config`.
///
/// These clients speak only HTTP/1.1, so a configuration that also offered `h2` would let an origin
/// select a protocol they cannot use. A configuration that is shared is copied, not changed.
pub fn http1(mut config: Arc<rustls::ClientConfig>) -> Arc<rustls::ClientConfig> {
    Arc::make_mut(&mut config).alpn_protocols = vec![b"http/1.1".to_vec()];

    config
}

/// Trust `webpki-roots`, use `aws-lc-rs`, and offer only `http/1.1`.
///
/// The crypto provider is named rather than taken from the process default, which is undefined
/// when a dependency graph enables more than one.
pub fn default_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    http1(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the aws-lc-rs provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}
