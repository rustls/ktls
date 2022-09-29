use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use rustls::{
    cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    },
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;
use tracing::{debug, Instrument};
use tracing_subscriber::EnvFilter;

#[tokio::test]
async fn ktls_server_rustls_client_tls_1_3_aes_128_gcm() {
    actual_test(&TLS13, TLS13_AES_128_GCM_SHA256).await;
}

#[tokio::test]
async fn ktls_server_rustls_client_tls_1_3_aes_256_gcm() {
    actual_test(&TLS13, TLS13_AES_256_GCM_SHA384).await;
}

#[tokio::test]
async fn ktls_server_rustls_client_tls_1_3_chacha20_poly1305() {
    actual_test(&TLS13, TLS13_CHACHA20_POLY1305_SHA256).await;
}

#[tokio::test]
async fn ktls_server_rustls_client_tls_1_2_ecdhe_aes_128_gcm() {
    actual_test(&TLS12, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).await;
}

#[tokio::test]
async fn ktls_server_rustls_client_tls_1_2_ecdhe_aes_256_gcm() {
    actual_test(&TLS12, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384).await;
}

#[tokio::test]
async fn ktls_server_rustls_client_tls_1_2_ecdhe_chacha20_poly1305() {
    actual_test(&TLS12, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256).await;
}

async fn actual_test(
    protocol_version: &'static SupportedProtocolVersion,
    cipher_suite: SupportedCipherSuite,
) {
    tracing_subscriber::fmt()
        // .with_env_filter(EnvFilter::new("rustls=trace,debug"))
        .with_env_filter(EnvFilter::new("debug"))
        .pretty()
        .init();

    let subject_alt_names = vec!["localhost".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    println!("{}", cert.serialize_pem().unwrap());
    println!("{}", cert.serialize_private_key_pem());

    let server_config = ServerConfig::builder()
        .with_cipher_suites(&[cipher_suite])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[protocol_version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(cert.serialize_der().unwrap())],
            rustls::PrivateKey(cert.serialize_private_key_der()),
        )
        .unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let ln = TcpListener::bind("[::]:0").await.unwrap();
    let addr = ln.local_addr().unwrap();

    tokio::spawn(
        async move {
            loop {
                let (stream, addr) = ln.accept().await.unwrap();
                debug!("Accepted TCP conn from {}", addr);
                let stream = acceptor.accept(stream).await.unwrap();
                debug!("Completed TLS handshake");
                let mut stream = ktls::config_ktls_server(stream).unwrap();
                debug!("Configured kTLS");

                debug!("Writing data");
                stream
                    .write_all(b"this is the server speaking\n")
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();

                debug!("Reading data");
                let mut buf: Vec<u8> = Default::default();
                stream.read_to_end(&mut buf).await.unwrap();
                assert_eq!(buf, b"this is the client speaking\n");
            }
        }
        .instrument(tracing::info_span!("server")),
    );

    let mut root_certs = RootCertStore::empty();
    root_certs
        .add(&rustls::Certificate(cert.serialize_der().unwrap()))
        .unwrap();

    let client_config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_certs)
        .with_no_client_auth();
    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut stream = tls_connector
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();
    stream
        .write_all(b"this is the client speaking\n")
        .await
        .unwrap();

    let mut buf: Vec<u8> = Default::default();
    stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"this is the server speaking\n");
}
