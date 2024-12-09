use futures_util::pin_mut;
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch::Sender;
use tokio::sync::{oneshot, watch};
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::LazyConfigAcceptor;

#[derive(Copy, Clone)]
enum TlsConfig {
    Disabled,
    Enabled,
}

async fn run_server(
    tcp_listener: TcpListener,
    mut shutdown_receiver: oneshot::Receiver<()>,
    tls_config: TlsConfig,
) {
    let enable_graceful_shutdown = true;

    let (wait_for_requests_to_complete_tx, wait_for_request_to_complete_rx) =
        watch::channel::<()>(());
    let (shut_down_connections_tx, shut_down_connections_rx) = watch::channel::<()>(());

    loop {
        tokio::select! {
            _ = &mut shutdown_receiver => {
                drop(shut_down_connections_rx);
                break;
            }
            conn = tcp_listener.accept() => {
                tokio::spawn(
                    handle_tcp_conn(
                        conn,
                        wait_for_request_to_complete_rx.clone(),
                        shut_down_connections_tx.clone(),
                        tls_config
                    )
                );
            }
        }
    }

    drop(wait_for_request_to_complete_rx);

    if enable_graceful_shutdown {
        wait_for_requests_to_complete_tx.closed().await;
    }
}

async fn handle_tcp_conn(
    conn: tokio::io::Result<(TcpStream, SocketAddr)>,
    indicate_connection_has_closed: watch::Receiver<()>,
    should_shut_down_connection: watch::Sender<()>,
    tls_config: TlsConfig,
) {
    let tcp_stream = conn.unwrap().0;

    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());

    match tls_config {
        TlsConfig::Disabled => {
            let stream = TokioIo::new(tcp_stream);

            handle_tokio_io_conn(builder, stream, should_shut_down_connection).await
        }
        TlsConfig::Enabled => {
            let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);
            tokio::pin!(acceptor);

            let start = acceptor.as_mut().await.unwrap();

            let config = rustls_server_config();
            let stream = start.into_stream(config).await.unwrap();
            let stream = TokioIo::new(stream);

            handle_tokio_io_conn(builder, stream, should_shut_down_connection).await
        }
    };

    drop(indicate_connection_has_closed);
}

fn rustls_server_config() -> Arc<tokio_rustls::rustls::ServerConfig> {
    let mut cert_reader = BufReader::new(Cursor::new(ssl_cert::TLS_CERTIFICATE_SELF_SIGNED));
    let mut key_reader = BufReader::new(Cursor::new(ssl_cert::TLS_PRIVATE_KEY_SELF_SIGNED));

    let key = pkcs8_private_keys(&mut key_reader)
        .into_iter()
        .map(|key| key.unwrap())
        .next()
        .unwrap();

    let certs = certs(&mut cert_reader)
        .into_iter()
        .map(|cert| cert.unwrap())
        .collect();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))
        .unwrap();

    Arc::new(config)
}

async fn handle_tokio_io_conn<T: AsyncRead + AsyncWrite + Unpin + 'static>(
    builder: hyper_util::server::conn::auto::Builder<TokioExecutor>,
    stream: TokioIo<T>,
    should_shut_down_connection: Sender<()>,
) {
    let should_shut_down_connection = should_shut_down_connection.closed();
    pin_mut!(should_shut_down_connection);

    let hyper_service = hyper::service::service_fn(move |_request: Request<Incoming>| async {
        let jitter_milliseconds = rand::thread_rng().gen_range(0..5);
        let sleep_time = Duration::from_millis(5) + Duration::from_millis(jitter_milliseconds);

        tokio::time::sleep(sleep_time).await;

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .unwrap();
        Ok::<_, &'static str>(response)
    });

    let conn = builder.serve_connection(stream, hyper_service);
    pin_mut!(conn);

    tokio::select! {
        result = conn.as_mut() => {
            if let Err(err) = result {
                dbg!(err);
            }
        }
        _ = should_shut_down_connection => {
            conn.as_mut().graceful_shutdown();
            let result = conn.as_mut().await;
            if let Err(err) = result {
                dbg!(err);
            }
        }
    };
}

/// The key and certificate were generated using the following command:
/// ```sh
/// # via https://letsencrypt.org/docs/certificates-for-localhost/#making-and-trusting-your-own-certificates
/// openssl req -x509 -out local_testing.crt -keyout local_testing.key \
///   -newkey rsa:2048 -nodes -sha256 \
///   -subj '/CN=localhost' -extensions EXT -config <( \
///    printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
/// ```
mod ssl_cert {
    pub(super) const TLS_CERTIFICATE_SELF_SIGNED: &'static str = r#"-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUaQDe0cAZUax+1IpET1vF8UFm3jswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MTAyMjExMjYyMFoXDTI0MTEy
MTExMjYyMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAsJGiYaWK0k6NT6J4uFyzPiTFGkjQ5K77dKBXrcwjz4LT
vsxUFAAyrV8GYIWJaaEKKD5WqF/B8WN1Di3+Ut8dxR7buDWgNN3R7qsp43IaTNsV
ORaN72DogMd94NzNVbAiqh+rjBNMyU/7AXwSifBbMzx/FL9KmGU5XejJtSx0EAd1
yV+cL+s/lWgDd0A82DdpZYNSfk5bQ6rcQis803VIqoVDM+4u85y/4wCR1QCQeGhr
YIeqwfGwf4o3pXB/spE2dB4ZU/QikYcTrUWVZ9Fup4UomUlggV9J0CuphjADdQxW
Nv3yH7HqgjmHl6h5Ei91ELjMH6TA2vwb3kv4bLoX/wIDAQABo1kwVzAUBgNVHREE
DTALgglsb2NhbGhvc3QwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MB0GA1UdDgQWBBTHjwqKi5dOeMSjlhhahDEEMPQBQjANBgkqhkiG9w0BAQsFAAOC
AQEACJo+lYhAtZgGkIZRYzJUSafVUsv2+5aFwDXtrNPWQxM6rCmVOHmZZlHUyrK/
dTGQbtO1/IkBAutBclVBa+lteXFqiOGWiYF+fESioBx7DEXQWgQJY4Q5bYSHUkNu
u7vKXPt+8aAaaKQA8kR5tEO/+4atlD619kor4SwajOMWX2johgNku5n6mZ+fldQj
5Bv7PhPWZjpBJoqaXkHWJiT449efJQsiHAXY73eLmUf4kuJjQLuPXwZ/TY3KeH8a
tuWXtYQp1pU60yRzrO8JJ/4gj1ly/bzs9CTaD/u6hmpbdMdgZRR5ZZqvK3KYyI82
3TfEIvddnICP7SnH+BUzCQJhXg==
-----END CERTIFICATE-----"#;

    pub(super) const TLS_PRIVATE_KEY_SELF_SIGNED: &'static str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwkaJhpYrSTo1P
oni4XLM+JMUaSNDkrvt0oFetzCPPgtO+zFQUADKtXwZghYlpoQooPlaoX8HxY3UO
Lf5S3x3FHtu4NaA03dHuqynjchpM2xU5Fo3vYOiAx33g3M1VsCKqH6uME0zJT/sB
fBKJ8FszPH8Uv0qYZTld6Mm1LHQQB3XJX5wv6z+VaAN3QDzYN2llg1J+TltDqtxC
KzzTdUiqhUMz7i7znL/jAJHVAJB4aGtgh6rB8bB/ijelcH+ykTZ0HhlT9CKRhxOt
RZVn0W6nhSiZSWCBX0nQK6mGMAN1DFY2/fIfseqCOYeXqHkSL3UQuMwfpMDa/Bve
S/hsuhf/AgMBAAECggEANKEsPBvaXaZxY4fDoPxspvzRzWxf65ImvJQgnlrHX86Y
q/n+o7mNYXT+Ex4qn9QTEXzHWse0KO3i0beu42fC2WNBzc4aMzfdH91gDn4PzdHN
qScKZoxFsUEFSdW21LA8HOZ0vTtxe13+LOqdIgWFQafqHzaHlxYw+8dr/DdEXxRC
xh2U9xlrgplz2VJW+NhvIUJoBpsvRJ0XK58Cs0L7+CHrdaUmtL6gLehp49wPy810
l2r168CcHw/HdYN2SKtA3l2EldyZ0BdgHnblq9ozY8isTCn1ccQE8sr1Id1rCj26
BlyVoZurukB1tYTtf9LvQnC6MPdcC7hbHkpYGvFcKQKBgQDrZmLhNNL8aj5iCwXg
BnqTFBSvkADPE7inI/iPy69Q3k87LHM27uUQy0wzJow4HrfQNSE3HN0gHo7K8/KB
n+vR0QCmYu5x7Uk994RBzub+8QfEPVP3yJP5MgbaT68L7BwiaWkVTU+sLIXVCxAl
OsYGtXrsvBdEVKLKiCCxVQR32QKBgQDABUTBKFCtlMNrK8MM9h/9ddMHv2QH6hd3
x8mijKEsLvjRDYUzAWd2a2Rabo4Wf9kv7R/dGR/3jWp+84rgmr9s/XS6pABoCYjJ
RNQ6kD+b+apSTybToTFJ78hhdfAeT4IzrxdbHMOOlZl86R8IpDzTubJAAMrnJxpX
+prSi8E/lwKBgGhX+BiPi75rcb+P10jYVlj/m7O+hz1DJqSf4zwKM2oLQN+f8mo1
NsBc/SfnPFxb8WqPQmvllXb5VJ5Nx/8BXkyg8kLOs5c4cTDQmIV7KxVyzdiEvsWk
2UKqlDMNAzCrtkTiqLvSizBsg95NixiVltW+eACb10xon8ha0vMIFnTxAoGBAIL/
lSZJgLDK+n6Uvl6LUsuxpCR296FGnHgE/pQ8aIAiE3FbTfG8FX9+SFpBbgH/eoXt
uX029M4H1g2BzM7qA4oxZ38k/3n6dy0IHdlOK3cXXpEEmrJqF5wfT47dzNCA4Yys
+LwZ5XfSq4HB8IAOu8iduPNdFw+XZ6t5tkHJQi9FAoGAU+39yLcc1c1gWQw4UCuU
D2vlTSSR7U0ji23goHYFGyIxmJNa1lpx/jxOlHSu99PNhx87FTDyW5HuoaayyUyw
dK+3pvS6KhSQMCrcpdAND5sRV3KsGGdYpy/ICmVFeK9f26VMOTN3jdCqLR+gnAaY
fuCBU0U/o2qoHC7VjsfzQZw=
-----END PRIVATE KEY-----"#;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    use hyper::StatusCode;
    use tokio::sync::mpsc;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// This always passes.
    #[tokio::test]
    async fn graceful_shutdown_without_tls() {
        test_graceful_shutdown(TlsConfig::Disabled).await
    }

    /// This always fails.
    #[tokio::test]
    async fn graceful_shutdown_with_tls() {
        test_graceful_shutdown(TlsConfig::Enabled).await
    }

    /// ## Steps
    /// - Start the server.
    /// - Send many concurrent requests to the server
    /// - Wait for any of the requests to receive a response.
    ///   Since the request handler takes a random amount of time we can be reasonably confident
    ///   that when we receive a response there are still some other requests that are in-progress.
    /// - Tell the server to shut down. We expect that there are still some in-progress requests.
    /// - Assert that we receive a 200 OK response for each request.
    ///   This means that the graceful shutdown process was successful.
    async fn test_graceful_shutdown(tls_config: TlsConfig) {
        init_tracing();

        // We repeat the test multiple times since the error does not always occur.
        const TEST_REPETITION_COUNT: usize = 100;

        for _ in 0..TEST_REPETITION_COUNT {
            tracing::info!("STARTING NEW ITERATION");

            let tcp_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = tcp_listener.local_addr().unwrap();

            let (shutdown_sender, shutdown_receiver) = oneshot::channel();
            let (successful_shutdown_tx, successful_shutdown_rx) = oneshot::channel();

            // Spawn the server in a separate async runtime so that once the server stops the
            // runtime will stop.
            // This ensures that when the server stops the runtime will stop and all other tasks
            // will be immediately dropped.
            // This way if we receive responses from the server we know that the server did not
            // shut down until after the request tasks finished running.
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .unwrap()
                    .block_on(async move {
                        run_server(tcp_listener, shutdown_receiver, tls_config).await;
                        successful_shutdown_tx.send(()).unwrap();
                    })
            });

            let mut request_handles = vec![];

            let (response_received_tx, mut response_received_rx) = mpsc::unbounded_channel();

            // An arbitrarily chosen number of requests to send concurrently.
            const CONCURRENT_REQUEST_COUNT: usize = 10;
            for _ in 0..CONCURRENT_REQUEST_COUNT {
                let response_received_tx = response_received_tx.clone();
                let handle = tokio::spawn(async move {
                    let result = send_get_request(addr, tls_config).await;
                    response_received_tx.send(()).unwrap();
                    result
                });
                request_handles.push(handle);
            }

            // Wait to receive the first response, and then shut down the server.
            // Since we sent many requests to the server we are confident that some of them have not
            // yet completed.
            // This means that if all requests get a 200 OK response then the graceful shutdown
            // process was successful.
            let _wait_for_first_response = response_received_rx.recv().await.unwrap();

            shutdown_sender.send(()).unwrap();

            // Check that every request received a 200 response.
            // We panic if a request ended with an error.
            for handle in request_handles {
                let result = handle.await.unwrap();
                match result {
                    Ok(status_code) => {
                        assert_eq!(status_code, StatusCode::OK);
                    }
                    Err(err) => {
                        panic!(
                            r#"
Error during the request/response cycle:
{err}
{err:?}
"#
                        )
                    }
                }
            }

            // Make sure that the server gets shut down.
            // If it was shut down and every request succeeded then we ca be confident that the
            // graceful shutdown process worked.
            let _did_shutdown = wait_max_3_seconds(successful_shutdown_rx).await;
        }
    }

    async fn send_get_request(
        addr: SocketAddr,
        tls_config: TlsConfig,
    ) -> Result<StatusCode, reqwest::Error> {
        let uri = match tls_config {
            TlsConfig::Disabled => {
                format!("http://{addr}")
            }
            TlsConfig::Enabled => {
                format!("https://{addr}")
            }
        };

        let client = reqwest::Client::builder()
            // We use a self-signed cert for localhost. Here we're trusting that self-signed cert.
            .danger_accept_invalid_certs(true)
            .build()?;
        let response = client.get(uri).send().await.map(|r| r.status());
        response
    }

    /// Used to prevent the test from running indefinitely.
    async fn wait_max_3_seconds<T>(fut: impl Future<Output = T>) {
        tokio::time::timeout(std::time::Duration::from_secs(3), fut)
            .await
            .unwrap();
    }

    fn init_tracing() {
        let tracing_subscriber_layer = tracing_subscriber::fmt::layer()
            // .pretty()
            .with_ansi(false)
            .with_target(true)
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339());

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| default_tracing_filters().into()),
            )
            .with(tracing_subscriber_layer)
            .init();
    }

    fn default_tracing_filters() -> &'static str {
        "hyper_graceful_shutdown_issue=trace,hyper=trace,hyper_util=trace"
    }
}
