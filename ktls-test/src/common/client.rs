//! Client

#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use ktls::utils::CompatibleCipherSuites;
use ktls_util::client::KtlsConnector;

pub mod verifier;

/// Example to get a `KtlsConnector`.
pub fn get_ktls_connector(compatible_cipher_suites: &CompatibleCipherSuites) -> KtlsConnector {
    static KTLS_CONNECTOR: OnceLock<KtlsConnector> = OnceLock::new();

    KTLS_CONNECTOR
        .get_or_init(|| {
            let mut crypto_provider = rustls::crypto::ring::default_provider();

            compatible_cipher_suites.filter(&mut crypto_provider.cipher_suites);

            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_protocol_versions(compatible_cipher_suites.protocol_versions)
                .expect("invalid protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(verifier::NoCertificateVerification::new())
                .with_no_client_auth();

            config.enable_secret_extraction = true;

            tracing::info!("Client config: {config:#?}");

            KtlsConnector::new(Arc::new(config))
        })
        .clone()
}
