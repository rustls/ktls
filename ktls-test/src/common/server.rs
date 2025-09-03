//! Server

#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use ktls::utils::CompatibleCipherSuites;
use ktls_util::server::KtlsAcceptor;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivateKeyDer;
use rustls::ServerConfig;

/// Example to get a global `KtlsAcceptor`.
pub fn get_ktls_acceptor(compatible_cipher_suites: &CompatibleCipherSuites) -> KtlsAcceptor {
    static KTLS_ACCEPTOR: OnceLock<KtlsAcceptor> = OnceLock::new();

    KTLS_ACCEPTOR
        .get_or_init(|| {
            let subject_alt_names = vec!["localhost".to_string()];

            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(subject_alt_names).unwrap();

            let mut crypto_provider = rustls::crypto::ring::default_provider();

            compatible_cipher_suites.filter(&mut crypto_provider.cipher_suites);

            let mut config = ServerConfig::builder_with_provider(Arc::new(crypto_provider))
                .with_protocol_versions(compatible_cipher_suites.protocol_versions)
                .expect("invalid protocol versions")
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::try_from(signing_key.serialized_der())
                        .expect("invalid key")
                        .clone_key(),
                )
                .expect("invalid certificate/key");

            config.enable_secret_extraction = true;

            tracing::info!("Server config: {config:#?}");

            KtlsAcceptor::new(Arc::new(config))
        })
        .clone()
}
