use std::{io::ErrorKind, sync::Arc};

use rcgen::generate_simple_self_signed;
use rustls::{
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;
use tracing::{debug, Instrument};
use tracing_subscriber::EnvFilter;

#[tokio::test]
async fn rustls_tls13_aes_128gcm() {
    tracing_subscriber::fmt()
        // .with_env_filter(EnvFilter::new("rustls=trace,tokio_rustls=trace,debug"))
        .with_env_filter(EnvFilter::new("debug"))
        .pretty()
        .init();

    let subject_alt_names = vec!["localhost".to_string()];

    let cert = generate_simple_self_signed(subject_alt_names).unwrap();
    println!("{}", cert.serialize_pem().unwrap());
    println!("{}", cert.serialize_private_key_pem());

    let server_config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS12, &TLS13])
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
        .with_cipher_suites(&[TLS13_AES_128_GCM_SHA256])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
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
    if let Err(e) = stream.read_to_end(&mut buf).await {
        if e.kind() == ErrorKind::UnexpectedEof {
            // fine for now, we don't send CLOSE_NOTIFY
        } else {
            panic!("unexpected error: {}", e);
        }
    }
    assert_eq!(buf, b"this is the server speaking\n");
}
