use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use http::header::HOST;
use pingora::{
    Error, Result,
    http::{RequestHeader, ResponseHeader},
    lb::{Backend, LoadBalancer, health_check},
    listeners::{self, TlsAccept},
    prelude::{HttpPeer, Opt, RoundRobin, background_service},
    protocols::tls::TlsRef,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
    tls::{pkey, ssl, x509::X509},
};
use std::collections::HashMap;

use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Default)]
pub struct Ctx {
    beta_user: bool,
}

pub struct LB {
    upstream: Arc<LoadBalancer<RoundRobin>>,
    sni: Option<Arc<str>>,
}

#[async_trait]
impl ProxyHttp for LB {
    // type CTX = ();
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let maybe_host = session
            .req_header()
            .headers
            .get(HOST)
            .and_then(|v| v.to_str().ok());

        let _cluster = if let Some(host) = maybe_host {
            match host {
                "abc.zennozenith.com" => 1,
                "example.com" => 1,
                "some.example.com" => 2,
                _ => 0,
            }
        } else {
            0
        };

        // let peer = if _cluster == 0 {
        //     Box::new(HttpPeer::new(
        //         ("1.1.1.1", 443),
        //         true,
        //         "one.one.one.one".to_string(),
        //     ))
        // } else {
        //     let upstream = self
        //         .upstream
        //         .select(b"", 256) // hash doesn't matter
        //         .unwrap();

        //     info!("upstream peer is: {:?}", upstream);

        //     // let peer = Box::new(HttpPeer::new(upstream, true, "one.one.one.one".to_string()));

        //     Box::new(HttpPeer::new(
        //         upstream,
        //         self.sni.is_some(),
        //         self.sni.clone().unwrap_or_default().to_string(),
        //     ))
        // };

        let peer = if session.req_header().uri.path().starts_with("/family") {
            let upstream = self
                .upstream
                .select(b"", 256) // hash doesn't matter
                .unwrap();

            info!("upstream peer is: {:?}", upstream);

            // let peer = Box::new(HttpPeer::new(upstream, true, "one.one.one.one".to_string()));

            Box::new(HttpPeer::new(
                upstream,
                self.sni.is_some(),
                self.sni.clone().unwrap_or_default().to_string(),
            ))
        } else {
            Box::new(HttpPeer::new(
                ("1.1.1.1", 443),
                true,
                "one.one.one.one".to_string(),
            ))
        };

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request
            .insert_header("Host", self.sni.as_deref().unwrap_or_default())
            .unwrap();

        Ok(())
    }

    // async fn early_request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()>
    // where
    //     Self::CTX: Send + Sync,
    // {
    //     if true {
    //         let mut resp = ResponseHeader::build(301, None)?;
    //         resp.append_header("Location", "https://google.com")?;

    //         let _ = session.write_response_header(Box::new(resp), true).await;
    //         return Ok(());
    //     }

    //     Ok(())
    // }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        ctx.beta_user = check_beta_user(session.req_header());

        // if true {
        //     let mut resp = ResponseHeader::build(301, None)?;
        //     resp.append_header("Location", "https://google.com")?;

        //     let _ = session.write_response_header(Box::new(resp), true).await;
        //     return Ok(true);
        // }

        Ok(false)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // replace existing header if any
        upstream_response
            .insert_header("Server", "MyGateway")
            .unwrap();
        // because we don't support h3
        upstream_response.remove_header("alt-svc");

        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let response_code = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());
        info!(
            "{} response code: {response_code}",
            self.request_summary(session, ctx)
        );

        // self.req_metric.inc();
    }
}

fn check_beta_user(req: &RequestHeader) -> bool {
    // some simple logic to check if user is beta
    req.headers.get("beta-flag").is_some()
}

type CertKey = (X509, pkey::PKey<pkey::Private>);
pub struct CertMap(HashMap<Arc<str>, CertKey>);

impl Deref for CertMap {
    type Target = HashMap<Arc<str>, CertKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CertMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CertMap {
    fn load_single_cert_pair(sni: &str) -> Result<CertKey, String> {
        // info!("sni: {sni}");
        let cert_path = format!("{}/tests/keys/{sni}/server.crt", env!("CARGO_MANIFEST_DIR"));
        let key_path = format!("{}/tests/keys/{sni}/key.pem", env!("CARGO_MANIFEST_DIR"));

        let cert = X509::from_pem(&std::fs::read(cert_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;

        // Load key
        let key =
            pkey::PKey::private_key_from_pem(&std::fs::read(key_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;

        Ok((cert, key))
    }

    pub fn new() -> Result<Self, String> {
        let mut map: HashMap<Arc<str>, CertKey> = HashMap::new();
        // Example: hard‑code domains and file paths
        let entries = vec![
            (
                "abc.zennozenith.com",
                "keys/some_domain_cert.crt",
                "keys/some_domain_key.pem",
            ),
            // ("one.one.one.one", "keys/one_cert.crt", "keys/one_key.pem"),
        ];

        for (hostname, _, _) in entries {
            let (cert, key) = Self::load_single_cert_pair(hostname)?;
            map.insert(hostname.into(), (cert, key));
        }

        Ok(Self(map))
    }
}

pub fn cert_map() -> &'static CertMap {
    static INSTANCE: OnceLock<CertMap> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        CertMap::new().unwrap_or_else(|ex| panic!("FATAL - WHILE LOADING CERTS - Cause: {ex:?}"))
    })
}

struct Certs;

#[async_trait]
impl TlsAccept for Certs {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        if let Some(sni) = ssl.servername(ssl::NameType::HOST_NAME)
            && let Some((cert, pkey)) = cert_map().get(sni)
        {
            ssl.set_certificate(cert)
                .unwrap_or_else(|ex| panic!("FATAL - WHILE SETTING SSL CERT - Cause: {ex:?}"));
            ssl.set_private_key(pkey).unwrap_or_else(|ex| {
                panic!("FATAL - WHILE SETIING SSL PRIVATE KEY - Cause: {ex:?}")
            });
        }
    }
}

// RUST_LOG=INFO cargo run --example load_balancer
// curl 127.0.0.1:6190 -H "Host: one.one.one.one"
// curl 127.0.0.1:6190 -H "Host: one.one.one.one" -H "beta-flag: 1"
fn main() {
    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // read command line arguments
    let opt = Opt::parse_args();
    let mut my_server = Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let mut backend1 = Backend::new_with_weight("0.0.0.0:3060", 1).unwrap();
    backend1.ext.insert(true);
    let mut backend2 = Backend::new_with_weight("0.0.0.0:3061", 1).unwrap();
    backend2.ext.insert(1u8);
    let backend3 = Backend::new_with_weight("0.0.0.0:3059", 1).unwrap();

    let mut upstreams = LoadBalancer::try_from_iter([backend1, backend2, backend3]).unwrap();

    // We add health check in the background so that the bad server is never selected.
    let hc = health_check::TcpHealthCheck::new();
    upstreams.set_health_check(hc);
    upstreams.health_check_frequency = Some(Duration::from_secs(1));

    let background = background_service("health check", upstreams);
    let upstreams = background.task();

    let mut lb = http_proxy_service(
        &my_server.configuration,
        LB {
            upstream: upstreams,
            sni: None,
        },
    );
    lb.add_tcp("0.0.0.0:6188");

    let cert_path = format!(
        "{}/tests/keys/abc.zennozenith.com/server.crt",
        env!("CARGO_MANIFEST_DIR")
    );
    let key_path = format!(
        "{}/tests/keys/abc.zennozenith.com/key.pem",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut tls_settings =
        listeners::tls::TlsSettings::intermediate(&cert_path, &key_path).unwrap();
    tls_settings.enable_h2();

    let certs = Certs;
    let mut tls_settings = listeners::tls::TlsSettings::with_callbacks(Box::new(certs))
        .expect("Unable to build TlsSettings");
    tls_settings.enable_h2();

    lb.add_tls_with_settings("0.0.0.0:6189", None, tls_settings);

    my_server.add_service(lb);
    my_server.add_service(background);
    my_server.run_forever();
}
