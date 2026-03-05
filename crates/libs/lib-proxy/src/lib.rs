mod config;

use std::sync::Arc;

use async_trait::async_trait;
use http::header::HOST;
use lib_proxy_config::RedirectHttpCode;
use pingora::{
    Error, ErrorSource, ErrorType,
    http::{RequestHeader, ResponseHeader},
    lb::Backend,
    listeners::{self, TlsAccept},
    prelude::{HttpPeer, Server},
    protocols::tls::TlsRef,
    proxy::{FailToProxy, ProxyHttp, Session, http_proxy_service},
    tls::ssl,
};

use crate::config::{
    Content, HostsToServerType, HostsToSslCert, Scheme, ServerType, SslCert,
    pingora_servers_from_config,
};

#[derive(Clone, Debug)]
struct MyErr {
    code: u16,
    message: &'static str,
}

impl MyErr {
    const fn new(code: u16, message: &'static str) -> Self {
        Self { code, message }
    }

    const fn missing_host_http_1_1() -> Self {
        Self::new(400, "text:Missing Host in HTTP/1.1")
    }

    const fn cannot_determine_host() -> Self {
        Self::new(400, "text:Cannot determine host")
    }

    const fn no_host_in_upstream() -> Self {
        Self::new(500, "text:No host in ctx in upstream_peer phase")
    }

    const fn no_upstream_peer() -> Self {
        Self::new(404, "text:No upstream peer")
    }

    const fn custom_server_content_path_io_err() -> Self {
        Self::new(502, "text:Custon server content path not readable")
    }

    const fn unreachable_upstream_peer_custom_server_type() -> Self {
        Self::new(
            500,
            "text:Custom host should not have reached upstream_peer phase",
        )
    }

    const fn unreachable_upstream_peer_redirect_server_type() -> Self {
        Self::new(
            500,
            "text:Redirect host should not have reached upstream_peer phase",
        )
    }

    const fn no_healthy_upstream_peer() -> Self {
        Self::new(503, "text:No healthy upstream peer")
    }

    const fn unreachable_upstream_request_filter_host_not_found() -> Self {
        Self::new(
            400,
            "text:Cannot determine host in upstream_request_filter phase",
        )
    }

    fn unreachable_upstream_peer_force_ssl() -> Self {
        Self::new(
            500,
            "text:Proxy *http* host should not have reached upstream_peer phase",
        )
    }
}

impl From<MyErr> for Box<Error> {
    fn from(value: MyErr) -> Self {
        Error::new(ErrorType::new_code(value.message, value.code))
    }
}

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

async fn redirect_to(
    location: &str,
    http_code: RedirectHttpCode,
    preserve_path: bool,
    session: &mut Session,
) -> Result<bool, Box<pingora::Error>> {
    let location = if preserve_path
        && let Some(path_and_query) = session.req_header().uri.path_and_query()
        && let Some(base) = location.strip_suffix('/')
    {
        format!("{base}{}", path_and_query.as_str())
    } else {
        location.to_string()
    };

    let mut resp = ResponseHeader::build(Into::<u16>::into(http_code), None)?;
    resp.append_header("Location", &location)?;
    session.write_response_header(Box::new(resp), true).await?;

    Ok(true)
}

fn is_http(session: &Session) -> bool {
    // matches!(session.req_header().uri.scheme(), Some(v) if v.as_str() == "http")

    // will provide a string like: TLSv1.3
    match session.digest() {
        Some(digest) => {
            if let Some(_ssl_digest) = &digest.ssl_digest {
                false
            } else {
                // unknown_tls_version
                true
            }
        }
        None => {
            // unknown_tls_digest
            false
        }
    }
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
        let header_host = session
            .get_header(HOST)
            .or_else(|| session.get_header(":authority"))
            .and_then(|v| v.to_str().ok());

        let uri_host = session.req_header().uri.host();

        // reject missing Host in HTTP/1.1
        if header_host.is_none() && !session.is_http2() {
            return Err(MyErr::missing_host_http_1_1().into());
        };

        ctx.host = match (header_host, uri_host) {
            (Some(h), _) => Some(Arc::from(h)),
            (None, Some(h)) => Some(Arc::from(h)), // optional fallback
            (None, None) => None,
        };

        let Some(host) = ctx.host.as_deref() else {
            return Err(MyErr::cannot_determine_host().into());
        };

        // Insert HOST header in [Self::upstream_request_filter]

        let server_type = self
            .map
            .iter()
            .find(|v| v.0.iter().any(|t| t.as_ref() == host))
            .map(|v| &v.1);

        if let Some(ServerType::Redirect(lib_proxy_config::Redirect {
            http_code,
            preserve_path,
            location,
        })) = server_type
        {
            return redirect_to(location.as_str(), *http_code, *preserve_path, session).await;
        };

        if let Some(ServerType::ProxyDirect { force_ssl, .. }) = server_type
            && *force_ssl
            && is_http(session)
        {
            let location = format!("https://{}", host);
            return redirect_to(
                &location,
                RedirectHttpCode::ParmanentRedirect,
                true,
                session,
            )
            .await;
        };

        if let Some(ServerType::ProxyLoadBalanced { force_ssl, .. }) = server_type
            && *force_ssl
            && is_http(session)
        {
            let location = format!("https://{}", host);
            return redirect_to(
                &location,
                RedirectHttpCode::ParmanentRedirect,
                true,
                session,
            )
            .await;
        };

        if let Some(ServerType::Custom {
            http_code,
            content,
            headers,
        }) = server_type
        {
            let body: bytes::Bytes = content
                .clone()
                .and_then(|c| match c {
                    Content::Bytes(b) => Some(bytes::Bytes::from(b)),
                    Content::Path { path } => std::fs::read(&path)
                        .inspect_err(|e| tracing::warn!("{:?}: {:?}", path, e))
                        .ok()
                        .map(bytes::Bytes::from),
                })
                .ok_or(MyErr::custom_server_content_path_io_err())?;

            let mut resp = ResponseHeader::build(*http_code, None)?;
            resp.insert_header("Content-Length", body.len().to_string())?;

            if let Some(header_map) = headers {
                for (key, value) in header_map.clone().into_iter() {
                    resp.insert_header(key, value)?
                }
            }
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(body), true).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let Some(host) = ctx.host.clone() else {
            return Err(MyErr::no_host_in_upstream().into());
        };

        let server_type = self
            .map
            .iter()
            .find(|v| v.0.iter().any(|t| t.as_ref() == host.as_ref()))
            .map(|v| &v.1);

        let Some(server_type) = server_type else {
            return Err(MyErr::no_upstream_peer().into());
        };

        let mut peer = match server_type {
            ServerType::Custom { .. } => {
                return Err(MyErr::unreachable_upstream_peer_custom_server_type().into());
            }
            ServerType::Redirect { .. } => {
                return Err(MyErr::unreachable_upstream_peer_redirect_server_type().into());
            }
            ServerType::ProxyDirect {
                force_ssl,
                addr,
                scheme: Scheme::Http,
            } => {
                if *force_ssl && is_http(session) {
                    return Err(MyErr::unreachable_upstream_peer_force_ssl().into());
                }
                Box::new(HttpPeer::new(addr, false, String::new()))
            }
            ServerType::ProxyDirect {
                force_ssl: _,
                addr,
                scheme: Scheme::Https { sni },
            } => Box::new(HttpPeer::new(addr, true, sni.to_string())),
            ServerType::ProxyLoadBalanced {
                upstream,
                force_ssl,
            } => {
                if *force_ssl && is_http(session) {
                    return Err(MyErr::unreachable_upstream_peer_force_ssl().into());
                }

                let backend = upstream
                    .select(b"", 256)
                    .ok_or(MyErr::no_healthy_upstream_peer())?;

                #[cfg(debug_assertions)]
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
        let Some(host) = ctx.host.clone().map(|v| v.to_string()) else {
            return Err(MyErr::unreachable_upstream_request_filter_host_not_found().into());
        };

        upstream_request.insert_header("Host", host)
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, _error: &Error) -> bool {
        false
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        _ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!("Peer: {}", peer));
        // only reused client connections where retry buffer is not truncated
        e.retry
            .decide_reuse(client_reused && !session.as_ref().retry_buffer_truncated());
        e
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        e
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        // #[cfg(debug_assertions)]
        // dbg!(&e);

        let (code, message): (u16, &'static str) = match e.etype() {
            ErrorType::HTTPStatus(code) => (*code, ""),
            ErrorType::CustomCode(message, code) => (*code, message),
            _ => {
                match e.esource() {
                    ErrorSource::Upstream => (502, ""),
                    ErrorSource::Downstream => {
                        match e.etype() {
                            ErrorType::WriteError
                            | ErrorType::ReadError
                            | ErrorType::ConnectionClosed => {
                                /* conn already dead */
                                (0, "")
                            }
                            _ => (400, ""),
                        }
                    }
                    ErrorSource::Internal | ErrorSource::Unset => (500, ""),
                }
            }
        };

        if code > 0 {
            let _body = bytes::Bytes::from(message);
            let body = match code {
                400 => bytes::Bytes::from(self.error_pages.page_400.to_vec()),
                403 => bytes::Bytes::from(self.error_pages.page_403.to_vec()),
                404 => bytes::Bytes::from(self.error_pages.page_404.to_vec()),
                500 => bytes::Bytes::from(self.error_pages.page_500.to_vec()),
                502 => bytes::Bytes::from(self.error_pages.page_502.to_vec()),
                503 => bytes::Bytes::from(self.error_pages.page_503.to_vec()),
                504 => bytes::Bytes::from(self.error_pages.page_504.to_vec()),
                _ => bytes::Bytes::from(self.error_pages.page_500.to_vec()),
            };

            if let Ok(mut resp) = ResponseHeader::build(code, None) {
                resp.insert_header("Content-Length", body.len().to_string())
                    .unwrap_or_else(|e| {
                        tracing::error!("failed to set header response to downstream: {e}");
                    });
                resp.insert_header("Content-Type", "text/html")
                    .unwrap_or_else(|e| {
                        tracing::error!("failed to set header response to downstream: {e}");
                    });

                session
                    .write_error_response(resp, body)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!("failed to send error response to downstream: {e}");
                    });
            } else {
                session.respond_error(code).await.unwrap_or_else(|e| {
                    tracing::error!("failed to send error response to downstream: {e}");
                });
            };
        }

        FailToProxy {
            error_code: code,
            // default to no reuse, which is safest
            can_reuse_downstream: false,
        }
    }

    fn request_summary(&self, session: &Session, _ctx: &Self::CTX) -> String {
        session.as_ref().request_summary()
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
