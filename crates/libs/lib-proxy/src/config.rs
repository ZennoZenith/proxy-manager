use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::SocketAddr,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::Arc,
};

use lib_proxy_config::{Http, Https};
use pingora::{
    lb::{Backend, Backends, LoadBalancer},
    prelude::{RoundRobin, background_service},
    services::background::GenBackgroundService,
    tls::{pkey, x509::X509},
};

#[derive(Debug, thiserror::Error, strum_macros::Display)]
pub enum Error {
    #[strum(to_string = "ServerNameNotUnique:: {0}")]
    ServerNameNotUnique(Box<str>),

    #[strum(to_string = "CertificateIo:: Path: {0:?} , Err: {1}")]
    CertificateIo(PathBuf, std::io::Error),

    #[strum(to_string = "CertificateFormat:: {0:?}")]
    CertificateFormat(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;
pub type BgService = GenBackgroundService<LoadBalancer<RoundRobin>>;

fn read_file_as_byte(path: Option<PathBuf>) -> Option<Arc<[u8]>> {
    path.and_then(|p| {
        std::fs::read(p.clone())
            .inspect_err(|e| tracing::warn!("Cannot read {:?}, Cause: {}", p, e))
            .ok()
    })
    .map(Arc::from)
}

#[derive(Clone, Debug)]
pub struct ErrorPages {
    pub(crate) page_default: Arc<[u8]>,
    pub(crate) page_400: Arc<[u8]>,
    pub(crate) page_403: Arc<[u8]>,
    pub(crate) page_404: Arc<[u8]>,
    pub(crate) page_500: Arc<[u8]>,
    pub(crate) page_502: Arc<[u8]>,
    pub(crate) page_503: Arc<[u8]>,
    pub(crate) page_504: Arc<[u8]>,
}

impl Default for ErrorPages {
    fn default() -> Self {
        let page_default = include_bytes!("../../../../examples/html/default.html")
            .to_vec()
            .into();
        let page_400 = include_bytes!("../../../../examples/html/400.html")
            .to_vec()
            .into();
        let page_403 = include_bytes!("../../../../examples/html/403.html")
            .to_vec()
            .into();
        let page_404 = include_bytes!("../../../../examples/html/404.html")
            .to_vec()
            .into();
        let page_500 = include_bytes!("../../../../examples/html/500.html")
            .to_vec()
            .into();
        let page_502 = include_bytes!("../../../../examples/html/502.html")
            .to_vec()
            .into();
        let page_503 = include_bytes!("../../../../examples/html/503.html")
            .to_vec()
            .into();
        let page_504 = include_bytes!("../../../../examples/html/504.html")
            .to_vec()
            .into();

        Self {
            page_default,
            page_400,
            page_403,
            page_404,
            page_500,
            page_502,
            page_503,
            page_504,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Scheme {
    Http,
    Https { sni: Box<str> },
}

impl From<lib_proxy_config::Scheme> for Scheme {
    fn from(value: lib_proxy_config::Scheme) -> Self {
        match value {
            lib_proxy_config::Scheme::Http => Self::Http,
            lib_proxy_config::Scheme::Https { sni } => Self::Https { sni: sni.into() },
        }
    }
}

impl Scheme {
    pub fn is_https(&self) -> bool {
        match self {
            Scheme::Http => false,
            Scheme::Https { .. } => true,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HostsToServerType {
    pub(crate) map: Vec<(Arc<[Box<str>]>, ServerType)>,
    pub(crate) error_pages: ErrorPages,
}

#[derive(Clone, Debug)]
pub(crate) struct HostsToSslCert(pub(crate) Vec<(Arc<[Box<str>]>, SslCert)>);

#[derive(Clone, Debug)]
pub(crate) struct PingoraHttpServer {
    pub(crate) ports: Box<[u16]>,
    pub(crate) host_to_server_type: HostsToServerType,
}

#[derive(Clone, Debug)]
pub(crate) struct PingoraHttpsServer {
    pub(crate) ports: Box<[u16]>,
    pub(crate) _http2: bool,
    pub(crate) host_to_server_type: HostsToServerType,
    pub(crate) host_to_certs: HostsToSslCert,
}

#[derive(Clone, Debug)]
pub(crate) struct SslCert {
    pub(crate) certificate: X509,
    pub(crate) private_key: pkey::PKey<pkey::Private>,
}

#[derive(Clone, Debug)]
pub(crate) enum Content {
    Bytes(Box<[u8]>),
    Path { path: PathBuf },
}

#[derive(Clone, Debug)]
pub(crate) enum ServerType {
    Custom {
        http_code: u16,
        content: Option<Content>,
        headers: Option<HashMap<String, String>>,
    },
    Redirect(lib_proxy_config::Redirect),
    ProxyDirect {
        addr: SocketAddr,
        scheme: Scheme,
        force_ssl: bool,
    },
    ProxyLoadBalanced {
        upstream: Upstream,
        force_ssl: bool,
    },
}

#[derive(Clone)]
pub(crate) struct Upstream(pub(crate) Arc<LoadBalancer<RoundRobin>>);

// TODO: Better Debug implementation
impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("0", &"some upsterams...")
            .finish()
    }
}

impl Deref for Upstream {
    type Target = Arc<LoadBalancer<RoundRobin>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Upstream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) fn pingora_servers_from_config(
    config: lib_proxy_config::Config,
) -> Result<(PingoraHttpServer, PingoraHttpsServer, Vec<BgService>)> {
    let error_pages = config
        .error_page
        .map(|pages| {
            let e_pages = ErrorPages::default();

            let page_default =
                read_file_as_byte(pages.page_default).unwrap_or(e_pages.page_default);
            let page_400 = read_file_as_byte(pages.page_400).unwrap_or(e_pages.page_400);
            let page_403 = read_file_as_byte(pages.page_403).unwrap_or(e_pages.page_403);
            let page_404 = read_file_as_byte(pages.page_404).unwrap_or(e_pages.page_404);
            let page_500 = read_file_as_byte(pages.page_500).unwrap_or(e_pages.page_500);
            let page_502 = read_file_as_byte(pages.page_502).unwrap_or(e_pages.page_502);
            let page_503 = read_file_as_byte(pages.page_503).unwrap_or(e_pages.page_503);
            let page_504 = read_file_as_byte(pages.page_504).unwrap_or(e_pages.page_504);

            ErrorPages {
                page_default,
                page_400,
                page_403,
                page_404,
                page_500,
                page_502,
                page_503,
                page_504,
            }
        })
        .unwrap_or_default();

    let http_ports: Vec<u16> = config
        .server
        .iter()
        .filter_map(|v| v.listen.http.as_ref())
        .flat_map(|http| http.port.iter().copied())
        .collect::<HashSet<u16>>()
        .into_iter()
        .collect();

    let https_ports: Vec<u16> = config
        .server
        .iter()
        .filter_map(|v| v.listen.https.as_ref())
        .flat_map(|https| https.port.iter().copied())
        .collect::<HashSet<u16>>()
        .into_iter()
        .collect();

    let mut server_names: Vec<String> = Vec::new();

    let mut background_services: Vec<BgService> = Vec::new();

    let mut http_host_to_server_type: Vec<(Arc<[Box<str>]>, ServerType)> = Vec::new();

    let mut https_host_to_server_type: Vec<(Arc<[Box<str>]>, ServerType)> = Vec::new();

    let mut http2 = false;

    let mut host_to_certs: Vec<(Arc<[Box<str>]>, SslCert)> = Vec::new();

    for server in config.server.into_iter() {
        if !server.enable {
            continue;
        }

        let listen_http: Option<Http> = server.listen.http;
        let listen_https: Option<Https> = server.listen.https;

        if listen_http.is_none() && listen_https.is_none() {
            // TODO: optimize vec allocation
            tracing::warn!(
                "No listen block for server names: {:?}",
                &Vec::from_iter(server.name.iter())
            );
            continue;
        }

        for server_name in server.name.iter() {
            if server_names.contains(server_name) {
                return Err(Error::ServerNameNotUnique(Box::from(server_name.clone())));
            }

            server_names.push(server_name.clone());
        }

        let boxed_server_names = server
            .name
            .iter()
            .map(|v| Box::from(v.clone()))
            .collect::<Arc<[Box<str>]>>();

        let server_type = match server.kind {
            lib_proxy_config::ServerType::Custom(lib_proxy_config::Custom {
                http_code,
                content,
                headers,
            }) => {
                let content: Option<Content> = content.map(|c| match c {
                    lib_proxy_config::Content::Text(b) => Content::Bytes(b.as_bytes().into()),
                    lib_proxy_config::Content::Bytes(b) => Content::Bytes(b),
                    lib_proxy_config::Content::Path { path, cache } => {
                        if cache {
                            // Read file into bytes, fallback to original path if read fails
                            std::fs::read(&path)
                                .map(|data| Content::Bytes(Box::from(data)))
                                .inspect_err(|e| tracing::warn!("{:?}: {:?}", path, e))
                                .unwrap_or(Content::Path { path })
                        } else {
                            Content::Path { path }
                        }
                    }
                });

                ServerType::Custom {
                    http_code,
                    content,
                    headers,
                }
            }
            lib_proxy_config::ServerType::Proxy(proxy_type) => match proxy_type {
                lib_proxy_config::ProxyType::Direct { scheme, address } => {
                    ServerType::ProxyDirect {
                        addr: address,
                        scheme: Scheme::from(scheme),
                        force_ssl: server.force_ssl,
                    }
                }
                lib_proxy_config::ProxyType::LoadBalanced { alg: _alg, backend } => {
                    let backends_set = backend
                        .iter()
                        .map(|backend| {
                            let mut b = Backend::new_with_weight(
                                &backend.address.to_string(),
                                backend.weight.get() as usize,
                            )
                            .unwrap_or_else(|ex| {
                                panic!("FATAL - WHILE CREATING BACKENDS - Cause: {ex:?}")
                            });

                            b.ext.insert(Scheme::from(backend.scheme.clone()));

                            b
                        })
                        .collect::<BTreeSet<Backend>>();

                    let discovery = pingora::lb::discovery::Static::new(backends_set);
                    let backends = Backends::new(discovery);

                    let mut load_balancer = LoadBalancer::<RoundRobin>::from_backends(backends);

                    use futures::FutureExt;
                    load_balancer
                        .update()
                        .now_or_never()
                        .expect("static should not block")
                        .expect("static should not error");

                    // #[cfg(debug_assertions)]
                    // dbg!(load_balancer.backends().get_backend());

                    let hc = pingora::lb::health_check::TcpHealthCheck::new();
                    load_balancer.set_health_check(hc);
                    load_balancer.health_check_frequency = Some(std::time::Duration::from_secs(1));

                    let bg_service = background_service("Tcp health check", load_balancer);
                    let load_balancer = bg_service.task();

                    background_services.push(bg_service);

                    ServerType::ProxyLoadBalanced {
                        force_ssl: server.force_ssl,
                        upstream: Upstream(load_balancer),
                    }
                }
            },
            lib_proxy_config::ServerType::Redirect(redirect) => ServerType::Redirect(redirect),
        };

        if listen_http.is_some() {
            http_host_to_server_type.push((boxed_server_names.clone(), server_type.clone()));
        }

        if let Some(Https {
            http2: server_http2,
            ssl_certificate,
            ssl_certificate_key,
            ..
        }) = listen_https
        {
            if server_http2 {
                http2 = true;
            }

            https_host_to_server_type.push((boxed_server_names.clone(), server_type));

            let ssl_certificate = X509::from_pem(
                &std::fs::read(&ssl_certificate)
                    .map_err(|e| Error::CertificateIo(ssl_certificate.clone(), e))?,
            )
            .map_err(|_| Error::CertificateFormat(ssl_certificate.clone()))?;

            let ssl_private_key = pkey::PKey::private_key_from_pem(
                &std::fs::read(&ssl_certificate_key)
                    .map_err(|e| Error::CertificateIo(ssl_certificate_key.clone(), e))?,
            )
            .map_err(|_| Error::CertificateFormat(ssl_certificate_key.clone()))?;

            let ssl_cert = SslCert {
                certificate: ssl_certificate,
                private_key: ssl_private_key,
            };

            host_to_certs.push((boxed_server_names, ssl_cert));
        };
    }

    let pingora_http_server = PingoraHttpServer {
        ports: http_ports.into(),
        host_to_server_type: HostsToServerType {
            map: http_host_to_server_type,
            error_pages: error_pages.clone(),
        },
    };

    let pingora_https_server = PingoraHttpsServer {
        _http2: http2,
        ports: https_ports.into(),
        host_to_server_type: HostsToServerType {
            map: https_host_to_server_type,
            error_pages,
        },
        host_to_certs: HostsToSslCert(host_to_certs),
    };

    Ok((
        pingora_http_server,
        pingora_https_server,
        background_services,
    ))
}
