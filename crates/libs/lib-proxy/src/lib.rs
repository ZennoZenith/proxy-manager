mod config;

use std::sync::Arc;

use async_trait::async_trait;
use http::header::HOST;
use pingora::{
    http::RequestHeader,
    lb::Backend,
    listeners::{self, TlsAccept},
    prelude::{HttpPeer, Server},
    protocols::tls::TlsRef,
    proxy::{ProxyHttp, Session, http_proxy_service},
    tls::ssl,
};

use crate::config::{
    HostsToProxyType, HostsToSslCert, ProxyType, Scheme, SslCert, pingora_servers_from_config,
};

fn backend_http_peer(server_name: &str, backend: Backend) -> Box<HttpPeer> {
    let tls = backend
        .ext
        .get::<Scheme>()
        .map(|v| v.is_https())
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

#[async_trait]
impl ProxyHttp for HostsToProxyType {
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
            .get_header(HOST)
            .or_else(|| session.get_header(":authority"))
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
            .0
            .iter()
            .find(|v| v.0.iter().any(|t| t.as_ref() == host.as_ref()))
            .map(|v| &v.1);

        #[cfg(debug_assertions)]
        if proxy_type.is_none() {
            tracing::warn!("No upstream peer for host: {}", host);
        }

        let Some(proxy_type) = proxy_type else {
            return Err(pingora::Error::new(pingora::ErrorType::Custom(
                "No proxy for give host",
            )));
        };

        let mut peer = match proxy_type {
            ProxyType::Proxy {
                addr,
                scheme: Scheme::Http,
            } => Box::new(HttpPeer::new(addr, false, String::new())),
            ProxyType::Proxy {
                addr,
                scheme: Scheme::Https { sni },
            } => Box::new(HttpPeer::new(addr, true, sni.to_string())),
            ProxyType::LoadBalancer { upstream, .. } => {
                let backend = upstream
                    .select(b"", 256) // hash doesn't matter
                    .unwrap();
                tracing::info!("upstream peer is: {:?}", backend);

                backend_http_peer(host.as_ref(), backend)
            }
        };

        #[cfg(debug_assertions)]
        {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }

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

#[async_trait]
impl TlsAccept for HostsToSslCert {
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
            .0
            .iter()
            .find(|v| v.0.iter().any(|t| t.as_ref() == sni))
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

pub fn run(config: lib_proxy_config::Config) -> config::Result<()> {
    let (http_server, https_server) = pingora_servers_from_config(config)?;

    // TODO: Pingora crate config
    // let opt = Opt::parse_args();
    // let mut my_server = Server::new(Some(opt)).unwrap();

    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    let mut lb = http_proxy_service(&my_server.configuration, http_server.host_to_proxy_type);

    for port in http_server.ports {
        let addr = format!("0.0.0.0:{}", port);
        tracing::info!("Listening http on addr:   http://{addr}");
        lb.add_tcp(&addr);
    }
    my_server.add_service(lb);

    let mut lb = http_proxy_service(&my_server.configuration, https_server.host_to_proxy_type);

    for port in https_server.ports {
        let addr = format!("0.0.0.0:{}", port);
        tracing::info!("Listening https on addr:  https://{addr}");

        let mut tls_settings = listeners::tls::TlsSettings::with_callbacks(Box::new(
            https_server.host_to_certs.clone(),
        ))
        .expect("Unable to build TlsSettings");
        tls_settings.enable_h2();

        lb.add_tls_with_settings(&addr, None, tls_settings);
    }

    my_server.add_service(lb);

    my_server.run_forever();
}
