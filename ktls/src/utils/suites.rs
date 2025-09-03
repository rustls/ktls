//! See [`CompatibleCipherSuites`]

use std::collections::HashSet;
use std::io;
use std::net::{TcpListener, TcpStream};

use rustls::{CipherSuite, SupportedCipherSuite, SupportedProtocolVersion};

use crate::setup::tls::TlsCryptoInfoTx;
use crate::setup::ulp::{setup_ulp, SetupError};

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone)]
/// A collection of compatible cipher suites for current kernel.
pub struct CompatibleCipherSuites {
    suites: HashSet<u16>,

    /// The supported protocol versions.
    pub protocol_versions: &'static [&'static SupportedProtocolVersion],
}

impl CompatibleCipherSuites {
    /// Probes the current Linux kernel for kTLS cipher suites compatibility.
    ///
    /// Returns `None` if the kernel does not support kTLS.
    ///
    /// # Notes
    ///
    /// - The caller may enable feature `rustls/tls12` to include TLS 1.2
    ///   support, or the protocol versions may be empty if only TLS 1.2 is
    ///   supported by current Linux kernel.
    /// - The caller may cache the result, as probing is expensive.
    ///
    /// ## Errors
    ///
    /// [`io::Error`].
    pub fn probe() -> io::Result<Option<Self>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;

        let local_addr = listener.local_addr()?;

        let mut inner = HashSet::new();

        let mut tls12_supported = false;
        let mut tls13_supported = false;

        macro_rules! test_param {
            ($method:ident, $data:ident, $version:expr, $cipher_type:expr) => {{
                let stream = match setup_ulp(TcpStream::connect(local_addr)?) {
                    Ok(stream) => stream,
                    Err(SetupError {
                        socket: Some(_), ..
                    }) => {
                        // kTLS is not supported
                        return Ok(None);
                    }
                    Err(SetupError { error, .. }) => {
                        return Err(error);
                    }
                };

                #[allow(unsafe_code)]
                // SAFETY: zeroed is fine for libc structs as we will set all the fields
                let mut data: libc::$data = unsafe { std::mem::zeroed() };

                data.info = libc::tls_crypto_info {
                    version: $version,
                    cipher_type: $cipher_type,
                };

                TlsCryptoInfoTx::$method(data).set(&stream).is_ok()
            }};
        }

        // Test TLS 1.2, AES-GCM-128
        if test_param!(
            custom_aes_128_gcm,
            tls12_crypto_info_aes_gcm_128,
            libc::TLS_1_2_VERSION,
            libc::TLS_CIPHER_AES_GCM_128
        ) {
            inner.insert(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into());
            inner.insert(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into());

            tls12_supported = true;
        }

        // Test TLS 1.2, AES-GCM-256
        if test_param!(
            custom_aes_256_gcm,
            tls12_crypto_info_aes_gcm_256,
            libc::TLS_1_2_VERSION,
            libc::TLS_CIPHER_AES_GCM_256
        ) {
            inner.insert(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into());
            inner.insert(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into());

            tls12_supported = true;
        }

        // Test TLS 1.2, ChaCha20-Poly1305
        if test_param!(
            custom_chacha20_poly1305,
            tls12_crypto_info_chacha20_poly1305,
            libc::TLS_1_2_VERSION,
            libc::TLS_CIPHER_CHACHA20_POLY1305
        ) {
            inner.insert(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into());
            inner.insert(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into());

            tls12_supported = true;
        }

        // Test TLS 1.3, AES-GCM-128
        if test_param!(
            custom_aes_128_gcm,
            tls12_crypto_info_aes_gcm_128,
            libc::TLS_1_3_VERSION,
            libc::TLS_CIPHER_AES_GCM_128
        ) {
            inner.insert(CipherSuite::TLS13_AES_128_GCM_SHA256.into());

            tls13_supported = true;
        }

        // Test TLS 1.3, AES-GCM-256
        if test_param!(
            custom_aes_256_gcm,
            tls12_crypto_info_aes_gcm_256,
            libc::TLS_1_3_VERSION,
            libc::TLS_CIPHER_AES_GCM_256
        ) {
            inner.insert(CipherSuite::TLS13_AES_256_GCM_SHA384.into());

            tls13_supported = true;
        }

        // Test TLS 1.3, ChaCha20-Poly1305
        if test_param!(
            custom_chacha20_poly1305,
            tls12_crypto_info_chacha20_poly1305,
            libc::TLS_1_3_VERSION,
            libc::TLS_CIPHER_CHACHA20_POLY1305
        ) {
            inner.insert(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256.into());

            tls13_supported = true;
        }

        Ok(Some(Self {
            suites: inner,
            protocol_versions: match (tls12_supported, tls13_supported) {
                (true, true) => rustls::DEFAULT_VERSIONS,
                // The first element is TLS 1.3
                (false, true) => &rustls::DEFAULT_VERSIONS[..1],
                // The first element is TLS 1.2 (maybe, but empty slice is OK, let the caller handle
                // it)
                (true, false) => &rustls::DEFAULT_VERSIONS[1..],
                // No supported versions
                (false, false) => return Ok(None),
            },
        }))
    }

    /// Filters the provided cipher suites list in place, removing suites
    /// which is incompatible.
    ///
    /// ## Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use ktls_util::suites::CompatibleCipherSuites;
    /// use rustls::crypto::CryptoProvider;
    ///
    /// // Get a crypto provider, for example, the default ring provider:
    /// let mut crypto_provider = rustls::crypto::ring::default_provider();
    ///
    /// // Filter it:
    /// let compatible_ciphers: &CompatibleCipherSuites = ...;
    /// compatible_ciphers.filter(&mut crypto_provider.cipher_suites);
    ///
    /// // Create client/server configuration  with`builder_with_provider`, for example:
    /// let root_store = ...;
    /// let config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
    ///     .with_protocol_versions(compatible_ciphers.protocol_versions)?
    ///     .with_root_certificates(root_store)
    ///     .with_no_client_auth();
    /// ```
    pub fn filter(&self, suite: &mut Vec<SupportedCipherSuite>) {
        suite.retain(|s| self.suites.contains(&s.suite().into()));
    }
}
