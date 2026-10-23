use super::*;
use tempfile::TempDir;

fn gen_keys() -> (TempDir, TlsPaths) {
    use std::{fs::File, io::Write};

    let dir = TempDir::with_prefix("kubert-test").expect("failed to create temporary directory");

    let cert = rcgen::generate_simple_self_signed(vec!["kubert.test.example.com".to_string()])
        .expect("failed to generate certs");

    let certs = {
        let path = dir.path().join("cert.pem");
        let mut file = File::create(&path).expect("failed to create cert file");
        let pem = cert.cert.pem();
        file.write_all(pem.as_bytes())
            .expect("failed to write certs PEM to tempfile");
        TlsCertPath(path)
    };

    let key = {
        let path = dir.path().join("key.pem");
        let mut file = File::create(&path).expect("failed to create private key file");
        let pem = cert.key_pair.serialize_pem();
        file.write_all(pem.as_bytes())
            .expect("failed to write private key PEM to tempfile");
        TlsKeyPath(path)
    };

    (dir, TlsPaths { key, certs })
}

#[tokio::test]
async fn load_tls_rustls() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (_tempdir, TlsPaths { key, certs }) = gen_keys();
    match super::tls_rustls::load_tls(&key, &certs).await {
        Ok(_) => println!("load_tls: success!"),
        Err(error) => panic!("load_tls failed! {error}"),
    }
}

#[cfg(feature = "clap")]
#[test]
fn server_args_http1_header_read_timeout_seconds() {
    use clap::Parser;

    let args = ServerArgs::try_parse_from(["test"]).expect("valid");
    assert_eq!(args.server_http1_header_read_timeout_seconds, 2);

    let args =
        ServerArgs::try_parse_from(["test", "--server-http1-header-read-timeout-seconds=100"])
            .expect("valid");
    assert_eq!(args.server_http1_header_read_timeout_seconds, 100);

    assert!(
        ServerArgs::try_parse_from(["test", "--server-http1-header-read-timeout-seconds=0"])
            .is_err()
    );
}

const SERVER_NAME: &str = "kubert.test.example.com";

async fn start_server(
    timeout_seconds: u64,
) -> (TempDir, drain::Signal, SpawnedServer, TlsCertPath) {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (dir, TlsPaths { key, certs }) = gen_keys();
    let args = ServerArgs {
        server_addr: "127.0.0.1:0".parse().unwrap(),
        server_tls_key: Some(key),
        server_tls_certs: Some(certs.clone()),
        server_http1_header_read_timeout_seconds: timeout_seconds,
    };
    let bound = args.bind().await.expect("bind must succeed");
    let (drain_tx, drain_rx) = drain::channel();
    let svc = tower::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
        Ok::<_, Infallible>(hyper::Response::new(String::from("ok")))
    });
    let srv = bound.spawn(svc, drain_rx);
    (dir, drain_tx, srv, certs)
}

async fn connect_http1(
    addr: SocketAddr,
    certs: &TlsCertPath,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, ServerName},
    };

    let pem = std::fs::read(&certs.0).expect("failed to read certs");
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        roots.add(cert.expect("valid cert")).expect("add root");
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp = TcpStream::connect(addr).await.expect("connect");
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(SERVER_NAME).unwrap(), tcp)
        .await
        .expect("TLS handshake")
}

async fn send_request<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    stream
        .write_all(format!("GET / HTTP/1.1\r\nHost: {SERVER_NAME}\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(6).any(|w| w == b"\r\n\r\nok") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response timed out")
            .expect("read response");
        assert_ne!(n, 0, "connection closed before response completed");
        buf.extend_from_slice(&chunk[..n]);
    }
    assert!(
        buf.starts_with(b"HTTP/1.1 200"),
        "unexpected response: {}",
        String::from_utf8_lossy(&buf)
    );
}

#[tokio::test]
async fn http1_header_read_timeout_closes_idle_connection() {
    use tokio::io::AsyncReadExt;

    let (_dir, _drain, srv, certs) = start_server(1).await;
    let mut stream = connect_http1(srv.local_addr(), &certs).await;
    send_request(&mut stream).await;

    tokio::time::sleep(Duration::from_millis(2500)).await;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("server must close the idle connection")
    {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("unexpected {n} bytes from idle connection"),
    }
}

#[tokio::test]
async fn http1_header_read_timeout_keeps_idle_connection() {
    let (_dir, _drain, srv, certs) = start_server(5).await;
    let mut stream = connect_http1(srv.local_addr(), &certs).await;
    send_request(&mut stream).await;

    tokio::time::sleep(Duration::from_millis(2500)).await;

    send_request(&mut stream).await;
}

#[tokio::test]
async fn bind_uses_http1_header_read_timeout_seconds() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (_dir, TlsPaths { key, certs }) = gen_keys();
    let bound = ServerArgs {
        server_addr: "127.0.0.1:0".parse().unwrap(),
        server_tls_key: Some(key),
        server_tls_certs: Some(certs),
        server_http1_header_read_timeout_seconds: 100,
    }
    .bind()
    .await
    .expect("bind must succeed");
    assert_eq!(
        bound.opts.http1_header_read_timeout,
        Duration::from_secs(100)
    );
}
