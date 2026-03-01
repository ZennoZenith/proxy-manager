use std::{
    collections::{BTreeSet, HashSet},
    net::SocketAddr,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::Arc,
};

use lib_proxy_config::{Http, Https, RedirectHttpCode};
use pingora::{
    lb::{Backend, Backends, LoadBalancer},
    prelude::{RoundRobin, background_service},
    services::background::GenBackgroundService,
    tls::{pkey, x509::X509},
};
use url::Url;

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
pub(crate) struct HostsToServerType(pub(crate) Vec<(Arc<[Box<str>]>, ServerType)>);

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
pub(crate) enum ServerType {
    Redirect {
        http_code: RedirectHttpCode,
        preserve_path: bool,
        location: Url,
    },
    ProxyDirect {
        addr: SocketAddr,
        scheme: Scheme,
    },
    ProxyLoadBalanced {
        upstream: Upstream,
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

        let server_type = match server.typ {
            lib_proxy_config::ServerType::Proxy(proxy_type) => match proxy_type {
                lib_proxy_config::ProxyType::Direct { scheme, address } => {
                    ServerType::ProxyDirect {
                        addr: address,
                        scheme: Scheme::from(scheme),
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
                        upstream: Upstream(load_balancer),
                    }
                }
            },
            lib_proxy_config::ServerType::Redirect(lib_proxy_config::Redirect {
                http_code,
                preserve_path,
                location,
            }) => ServerType::Redirect {
                http_code,
                preserve_path,
                location,
            },
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
        host_to_server_type: HostsToServerType(http_host_to_server_type),
    };

    let pingora_https_server = PingoraHttpsServer {
        _http2: http2,
        ports: https_ports.into(),
        host_to_server_type: HostsToServerType(https_host_to_server_type),
        host_to_certs: HostsToSslCert(host_to_certs),
    };

    Ok((
        pingora_http_server,
        pingora_https_server,
        background_services,
    ))
}
