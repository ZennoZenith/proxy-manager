use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use http::header::HOST;
use pingora::{
    http::RequestHeader,
    lb::Backend,
    listeners::{self, TlsAccept},
    prelude::{HttpPeer, Opt},
    protocols::tls::TlsRef,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
    tls::ssl,
};

use crate::{
    config::Scheme,
    server_config::{ProxyType, SslCert},
    utils::Port,
};

mod config;
mod server_config;
mod utils;

fn backend_http_peer(server_name: &str, backend: Backend) -> Box<HttpPeer> {
    let tls = backend
        .ext
        .get::<Scheme>()
        .map(|v| match v {
            Scheme::Http => false,
            Scheme::Https => true,
        })
        .unwrap_or(false);

    let sni = backend
        .ext
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| server_name.to_string());

    Box::new(HttpPeer::new(backend, tls, sni))
}

#[derive(Default)]
struct Ctx {
    host: Option<Arc<str>>,
}

struct ProxyHttpServer {
    port: u16,
    host_to_proxy_type: Vec<(Box<str>, ProxyType)>,
}

#[async_trait]
impl ProxyHttp for ProxyHttpServer {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx::default()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        ctx.host = session
            .get_header(":authority")
            .or_else(|| session.get_header(HOST))
            .and_then(|v| v.to_str().ok())
            .or_else(|| session.req_header().uri.host())
            .map(Arc::from);

        if let Some(host) = ctx.host.clone() {
            session
                .req_header_mut()
                .insert_header("Host", host.to_string())
                .unwrap();
        }

        // if true {
        //     let mut resp = ResponseHeader::build(301, None)?;
        //     resp.append_header("Location", "https://google.com")?;

        //     let _ = session.write_response_header(Box::new(resp), true).await;
        //     return Ok(true);
        // }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let Some(host) = ctx.host.clone() else {
            return Err(pingora::Error::new(pingora::ErrorType::Custom(
                "No host in ctx in upstream_peer phase",
            )));
        };

        let proxy_type = self
            .host_to_proxy_type
            .iter()
            .find(|v| v.0.as_ref() == host.as_ref())
            .map(|v| &v.1);

        let Some(proxy_type) = proxy_type else {
            return Err(pingora::Error::new(pingora::ErrorType::Custom(
                "No proxy for give host",
            )));
        };

        let peer = match proxy_type {
            ProxyType::Proxy { addr, tls, sni } => {
                Box::new(HttpPeer::new(addr, *tls, sni.to_string()))
            }
            ProxyType::LoadBalancer { upstream, .. } => {
                let backend = upstream
                    .select(b"", 256) // hash doesn't matter
                    .unwrap();
                tracing::info!("upstream peer is: {:?}", backend);

                backend_http_peer(host.as_ref(), backend)
            }
        };

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        upstream_request
            .insert_header(
                "Host",
                ctx.host.clone().map(|v| v.to_string()).unwrap_or_default(),
            )
            .unwrap();

        Ok(())
    }
}

struct Certs {
    host_to_cert: Vec<(Box<str>, SslCert)>,
}

#[async_trait]
impl TlsAccept for Certs {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let Some(sni) = ssl.servername(ssl::NameType::HOST_NAME) else {
            tracing::warn!(
                "Cannot extract sni. Raw sni: {:?}",
                ssl.servername_raw(ssl::NameType::HOST_NAME)
            );
            return;
        };

        let Some(SslCert {
            certificate,
            private_key,
        }) = self
            .host_to_cert
            .iter()
            .find(|v| v.0.as_ref() == sni)
            .map(|v| &v.1)
        else {
            tracing::warn!("Ssl cert not found for sni: {sni}");
            return;
        };

        if let Err(ex) = ssl.set_certificate(certificate) {
            tracing::warn!("While setting ssl cert - Cause: {ex:?}")
        };

        if let Err(ex) = ssl.set_private_key(private_key) {
            tracing::warn!("While setiing ssl private key - cause: {ex:?}")
        };
    }
}

fn main() -> color_eyre::Result<()> {
    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_file_path = format!("{}/examples/config.toml", env!("CARGO_MANIFEST_DIR"));
    let config = server_config::Config::load_from_path(config_file_path)?;

    #[cfg(debug_assertions)]
    dbg!(&config);

    let opt = Opt::parse_args();
    let mut my_server = Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let servers = config.servers();

    let http_ports = servers
        .iter()
        .flat_map(|v| v.listen_http.iter().map(|t| t.port))
        .collect::<HashSet<Port>>();

    let https_ports = servers
        .iter()
        .flat_map(|v| v.listen_https.iter().map(|t| t.port))
        .collect::<HashSet<Port>>();

    let proxy_http_servers = http_ports
        .into_iter()
        .map(|port| {
            let host_to_proxy_type = servers
                .iter()
                .filter(|v| v.listen_http.iter().any(|t| t.port == port))
                .map(|v| (Into::<Box<str>>::into(v.name.clone()), v.proxy_type.clone()))
                .collect::<Vec<(Box<str>, ProxyType)>>();
            ProxyHttpServer {
                port: port.into(),
                host_to_proxy_type,
            }
        })
        .collect::<Vec<ProxyHttpServer>>();

    let proxy_https_servers_and_certs = https_ports
        .into_iter()
        .map(|port| {
            let host_to_proxy_type = servers
                .iter()
                .filter(|v| v.listen_https.iter().any(|t| t.port == port))
                .map(|v| (Into::<Box<str>>::into(v.name.clone()), v.proxy_type.clone()))
                .collect::<Vec<(Box<str>, ProxyType)>>();

            let host_to_cert = servers
                .iter()
                .filter(|v| v.listen_https.iter().any(|t| t.port == port))
                .map(|v| {
                    (
                        Into::<Box<str>>::into(v.name.clone()),
                        v.listen_https
                            .iter()
                            .find(|t| t.port == port)
                            .map(|t| t.ssl_cert.clone())
                            .expect("Https port server shoud have been found"),
                    )
                })
                .collect::<Vec<(Box<str>, SslCert)>>();

            (
                ProxyHttpServer {
                    port: port.into(),
                    host_to_proxy_type,
                },
                Certs { host_to_cert },
            )
        })
        .collect::<Vec<(ProxyHttpServer, Certs)>>();

    for proxy_http_server in proxy_http_servers.into_iter() {
        let addr = format!("0.0.0.0:{}", proxy_http_server.port);
        println!("Listening http on addr:  {addr}");

        let mut lb = http_proxy_service(&my_server.configuration, proxy_http_server);
        lb.add_tcp(&addr);

        my_server.add_service(lb);
    }

    for (proxy_https_server, certs) in proxy_https_servers_and_certs.into_iter() {
        let addr = format!("0.0.0.0:{}", proxy_https_server.port);
        println!("Listening https on addr: {addr}");

        let mut tls_settings = listeners::tls::TlsSettings::with_callbacks(Box::new(certs))
            .expect("Unable to build TlsSettings");
        tls_settings.enable_h2();

        let mut lb = http_proxy_service(&my_server.configuration, proxy_https_server);
        lb.add_tls_with_settings(&addr, None, tls_settings);

        my_server.add_service(lb);
    }

    my_server.run_forever();
}
