use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use pingora::{
    lb::{Backend, LoadBalancer, health_check},
    prelude::RoundRobin,
    tls::{pkey, x509::X509},
};

use crate::{
    config::{self, Scheme},
    utils::{NonEmptyTrimedStr, Port},
};

#[derive(Clone)]
pub(crate) struct Upstream(Arc<LoadBalancer<RoundRobin>>);

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

#[derive(Debug, thiserror::Error, strum_macros::Display)]
pub enum Error {
    #[strum(to_string = "Config:: {0}")]
    Config(#[from] config::Error),

    #[strum(to_string = "Unreachable:: {0}")]
    Unreachable(&'static str),

    #[strum(to_string = "CertificateIo:: Path: {0:?} , Err: {1}")]
    CertificateIo(PathBuf, std::io::Error),

    #[strum(to_string = "CertificateFormat:: {0:?}")]
    CertificateFormat(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    servers: Vec<Server>,
}

impl Config {
    #[allow(unused)]
    pub fn load_from_toml_str(toml: &str) -> Result<Self> {
        let config = config::Config::load_from_toml_str(toml)?;
        config.try_into()
    }

    pub fn load_from_path<T: AsRef<Path>>(path: T) -> Result<Self> {
        let config = config::Config::load_from_path(path)?;
        config.try_into()
    }

    pub fn servers(self) -> Arc<[Server]> {
        self.servers.into()
    }
}

impl TryFrom<config::Config> for Config {
    type Error = Error;

    fn try_from(value: config::Config) -> std::result::Result<Self, Self::Error> {
        let load_balancers: Vec<LB> = (&value).into();

        let mut servers = Vec::with_capacity(value.servers().len());

        for server in value.servers() {
            if !server.enable {
                continue;
            }

            let proxy_type = match (&server.proxy, &server.load_balancer_name) {
                (None, Some(load_balancer_name)) => load_balancers
                    .iter()
                    .find(|v| &v.name == load_balancer_name)
                    .map(|LB { upstream, .. }| ProxyType::LoadBalancer {
                        upstream: upstream.clone(),
                    })
                    .ok_or(Error::Unreachable(
                        "Load balancer name should have be found",
                    ))?,
                (
                    Some(config::Proxy {
                        scheme,
                        address,
                        sni,
                    }),
                    None,
                ) => ProxyType::Proxy {
                    addr: *address,
                    tls: scheme == &Scheme::Https,
                    sni: sni.clone().map(|v| v.as_ref().into()).unwrap_or_default(),
                },
                _ => return Err(Error::Unreachable("Proxy Type cannot be created")),
            };

            let listen_http = server
                .http
                .iter()
                .map(|config::Http { listen_port }| ListenHttp { port: *listen_port })
                .collect::<Vec<ListenHttp>>();
            let listen_http = Arc::from(listen_http);

            let listen_https = server
                .https
                .iter()
                .map(
                    |config::Https {
                         listen_port,
                         http2,
                         ssl_certificate,
                         ssl_certificate_key,
                     }| {
                        let ssl_certificate = X509::from_pem(
                            &std::fs::read(ssl_certificate)
                                .map_err(|e| Error::CertificateIo(ssl_certificate.clone(), e))?,
                        )
                        .map_err(|_| Error::CertificateFormat(ssl_certificate.clone()))?;

                        let ssl_private_key = pkey::PKey::private_key_from_pem(
                            &std::fs::read(ssl_certificate_key).map_err(|e| {
                                Error::CertificateIo(ssl_certificate_key.clone(), e)
                            })?,
                        )
                        .map_err(|_| Error::CertificateFormat(ssl_certificate_key.clone()))?;

                        Ok(ListenHttps {
                            port: *listen_port,
                            http2: *http2,
                            ssl_cert: SslCert {
                                certificate: ssl_certificate,
                                private_key: ssl_private_key,
                            },
                        })
                    },
                )
                .collect::<Result<Vec<ListenHttps>>>()
                .map(Arc::from)?;

            servers.push(Server {
                name: server.name.clone(),
                listen_http,
                listen_https,
                proxy_type,
            });
        }

        Ok(Self { servers })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Server {
    pub(crate) name: NonEmptyTrimedStr,
    pub(crate) listen_http: Arc<[ListenHttp]>,
    pub(crate) listen_https: Arc<[ListenHttps]>,
    pub(crate) proxy_type: ProxyType,
}

#[derive(Clone, Debug)]
pub(crate) struct ListenHttp {
    pub(crate) port: Port,
}

#[derive(Clone, Debug)]
pub(crate) struct ListenHttps {
    pub(crate) port: Port,
    #[allow(unused)]
    pub(crate) http2: bool,
    pub(crate) ssl_cert: SslCert,
}

#[derive(Clone, Debug)]
pub(crate) struct SslCert {
    pub(crate) certificate: X509,
    pub(crate) private_key: pkey::PKey<pkey::Private>,
}

#[derive(Clone, Debug)]
pub(crate) enum ProxyType {
    Proxy {
        addr: SocketAddr,
        tls: bool,
        sni: Arc<str>,
    },
    LoadBalancer {
        upstream: Upstream,
    },
}

/// LoadBalancer
#[derive(Clone)]
struct LB {
    name: NonEmptyTrimedStr,
    upstream: Upstream,
    // health_check_service: GenBackgroundService<LoadBalancer<Weighted<RoundRobin>>>,
}

impl From<&config::Config> for Vec<LB> {
    fn from(value: &config::Config) -> Self {
        value
            .load_balancers()
            .iter()
            .map(|load_balancer| {
                let backends = load_balancer
                    .backend
                    .iter()
                    .map(|backend| {
                        let mut b =
                            Backend::new_with_weight(&backend.address.to_string(), backend.weight)
                                .unwrap_or_else(|ex| {
                                    panic!("FATAL - WHILE CREATING BACKENDS - Cause: {ex:?}")
                                });
                        b.ext.insert(backend.scheme);
                        b.ext.insert(backend.sni.clone());

                        b
                    })
                    .collect::<Vec<Backend>>();

                let mut upstream = LoadBalancer::try_from_iter(backends).unwrap();
                let hc = health_check::TcpHealthCheck::new();
                upstream.set_health_check(hc);
                upstream.health_check_frequency = Some(Duration::from_secs(1));

                // let health_check_service = background_service("health check", upstream);
                // let upstream = health_check_service.task();
                //
                let upstream = Arc::new(upstream);

                LB {
                    name: load_balancer.name.clone(),
                    upstream: Upstream(upstream),
                    // health_check_service,
                }
            })
            .collect()
    }
}
