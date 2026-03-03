mod config;

use std::sync::Arc;

use async_trait::async_trait;
use http::header::HOST;
use pingora::{
    http::{RequestHeader, ResponseHeader},
    lb::Backend,
    listeners::{self, TlsAccept},
    prelude::{HttpPeer, Server},
    protocols::tls::TlsRef,
    proxy::{ProxyHttp, Session, http_proxy_service},
    tls::ssl,
};

use crate::config::{
    Content, HostsToServerType, HostsToSslCert, Scheme, ServerType, SslCert,
    pingora_servers_from_config,
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
impl ProxyHttp for HostsToServerType {
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

        let Some(host) = ctx.host.as_deref() else {
            tracing::warn!("Unable to extract host header");
            return Ok(true);
        };

        session
            .req_header_mut()
            .insert_header("Host", host.to_string())
            .unwrap();

        let server_type = self
            .0
            .iter()
            .find(|v| v.0.iter().any(|t| t.as_ref() == host))
            .map(|v| &v.1);

        if let Some(ServerType::Redirect(lib_proxy_config::Redirect {
            http_code,
            preserve_path,
            location,
        })) = server_type
        {
            let mut final_location = location.as_str().to_owned();

            if *preserve_path
                && let Some(path_and_query) = session.req_header().uri.path_and_query()
                && let Some(base) = final_location.strip_suffix('/')
            {
                final_location = format!("{base}{}", path_and_query.as_str());
            }

            let mut resp = ResponseHeader::build(Into::<u16>::into(http_code), None)?;
            resp.append_header("Location", &final_location)?;
            session.write_response_header(Box::new(resp), true).await?;

            return Ok(true);
        };

        if let Some(ServerType::Custom {
            http_code,
            content,
            headers,
        }) = server_type
        {
            let body: Option<bytes::Bytes> = content.clone().and_then(|c| match c {
                Content::Bytes(b) => Some(bytes::Bytes::from(b)),
                Content::Path { path, .. } => std::fs::read(&path)
                    .inspect_err(|e| tracing::warn!("{:?}: {:?}", path, e))
                    .ok()
                    .map(bytes::Bytes::from),
            });

            let mut resp = ResponseHeader::build(*http_code, None)?;

            if let Some(b) = &body {
                resp.insert_header("Content-Length", b.len().to_string())?;
            }

            if let Some(header_map) = headers {
                for (key, value) in header_map.clone().into_iter() {
                    resp.insert_header(key, value)?
                }
            }
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(body, true).await?;
            return Ok(true);
        }

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

        let server_type = self
            .0
            .iter()
            .find(|v| v.0.iter().any(|t| t.as_ref() == host.as_ref()))
            .map(|v| &v.1);

        #[cfg(debug_assertions)]
        if server_type.is_none() {
            tracing::warn!("No upstream peer for host: {}", host);
        }

        let Some(server_type) = server_type else {
            return Err(pingora::Error::new(pingora::ErrorType::Custom(
                "No proxy for give host",
            )));
        };

        let mut peer = match server_type {
            ServerType::Custom { .. } => {
                tracing::error!("Custom host should not have reached upstream_peer phase");
                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "Custom host should not have reached upstream_peer phase",
                )));
            }
            ServerType::Redirect { .. } => {
                tracing::error!("Redirect host should not have reached upstream_peer phase");
                return Err(pingora::Error::new(pingora::ErrorType::Custom(
                    "Redirect host should not have reached upstream_peer phase",
                )));
            }
            ServerType::ProxyDirect {
                addr,
                scheme: Scheme::Http,
            } => Box::new(HttpPeer::new(addr, false, String::new())),
            ServerType::ProxyDirect {
                addr,
                scheme: Scheme::Https { sni },
            } => Box::new(HttpPeer::new(addr, true, sni.to_string())),
            ServerType::ProxyLoadBalanced { upstream, .. } => {
                let backend = upstream.select(b"", 256).unwrap();
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
    let (http_server, https_server, background_services) = pingora_servers_from_config(config)?;

    // TODO: Pingora crate config
    // let opt = Opt::parse_args();
    // let mut my_server = Server::new(Some(opt)).unwrap();

    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    let mut lb = http_proxy_service(&my_server.configuration, http_server.host_to_server_type);

    for port in http_server.ports {
        let addr = format!("0.0.0.0:{}", port);
        tracing::info!("Listening http on addr:   http://{addr}");
        lb.add_tcp(&addr);
    }
    my_server.add_service(lb);

    let mut lb = http_proxy_service(&my_server.configuration, https_server.host_to_server_type);

    for port in https_server.ports {
        let addr = format!("0.0.0.0:{}", port);
        tracing::info!("Listening https on addr:  https://{addr}");

        let mut tls_settings = listeners::tls::TlsSettings::with_callbacks(Box::new(
            https_server.host_to_certs.clone(),
        ))
        .expect("Unable to build TlsSettings");

        // TODO: Http2 is enabled for all routes
        tls_settings.enable_h2();

        lb.add_tls_with_settings(&addr, None, tls_settings);
    }

    my_server.add_service(lb);

    for background_service in background_services.into_iter() {
        my_server.add_service(background_service);
    }

    my_server.run_forever();
}
