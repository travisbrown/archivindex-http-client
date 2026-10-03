//! The TLS client configuration the `rustls` backends start from.

use std::sync::Arc;

/// Trust `webpki-roots` and use `aws-lc-rs`.
///
/// The crypto provider is named rather than taken from the process default, which is undefined
/// when a dependency graph enables more than one.
pub fn default_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the aws-lc-rs provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}
