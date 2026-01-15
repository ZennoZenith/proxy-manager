use std::{
    collections::HashSet,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::Arc,
};

use pingora::{
    lb::{Backend, LoadBalancer},
    prelude::RoundRobin,
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

#[derive(Clone, Debug)]
pub(crate) enum Scheme {
    Http,
    Https { sni: Box<str> },
}

impl From<lib_config::Scheme> for Scheme {
    fn from(value: lib_config::Scheme) -> Self {
        match value {
            lib_config::Scheme::Http => Self::Http,
            lib_config::Scheme::Https { sni } => Self::Https { sni: sni.into() },
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
pub(crate) struct HostsToProxyType(pub(crate) Vec<(Arc<[Box<str>]>, ProxyType)>);

#[derive(Clone, Debug)]
pub(crate) struct HostsToSslCert(pub(crate) Vec<(Arc<[Box<str>]>, SslCert)>);

#[derive(Clone, Debug)]
pub(crate) struct PingoraHttpServer {
    pub(crate) ports: Box<[u16]>,
    pub(crate) host_to_proxy_type: HostsToProxyType,
}

#[derive(Clone, Debug)]
pub(crate) struct PingoraHttpsServer {
    pub(crate) ports: Box<[u16]>,
    pub(crate) http2: bool,
    pub(crate) host_to_proxy_type: HostsToProxyType,
    pub(crate) host_to_certs: HostsToSslCert,
}

#[derive(Clone, Debug)]
pub(crate) struct SslCert {
    pub(crate) certificate: X509,
    pub(crate) private_key: pkey::PKey<pkey::Private>,
}

#[derive(Clone, Debug)]
pub(crate) enum ProxyType {
    Proxy { addr: SocketAddr, scheme: Scheme },
    LoadBalancer { upstream: Upstream },
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
    config: lib_config::Config,
) -> Result<(PingoraHttpServer, PingoraHttpsServer)> {
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
        .flat_map(|http| http.port.iter().copied())
        .collect::<HashSet<u16>>()
        .into_iter()
        .collect();

    let mut server_names: Vec<String> = Vec::new();

    let mut http_host_to_proxy_type: Vec<(Arc<[Box<str>]>, ProxyType)> = Vec::new();

    let mut https_host_to_proxy_type: Vec<(Arc<[Box<str>]>, ProxyType)> = Vec::new();

    let mut http2 = false;

    let mut host_to_certs: Vec<(Arc<[Box<str>]>, SslCert)> = Vec::new();

    for server in config.server.into_iter() {
        if !server.enable {
            continue;
        }

        // TODO: optimize vec allocation
        if server.listen.http.is_none() && server.listen.https.is_none() {
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

        let proxy_type = match server.proxy {
            lib_config::ProxyType::Proxy { scheme, address } => ProxyType::Proxy {
                addr: address,
                scheme: Scheme::from(scheme),
            },
            lib_config::ProxyType::LoadBalancer { alg: _alg, backend } => {
                let backends = backend
                    .iter()
                    .map(|backend| {
                        let mut b = Backend::new_with_weight(
                            &backend.address.to_string(),
                            backend.weight as usize,
                        )
                        .unwrap_or_else(|ex| {
                            panic!("FATAL - WHILE CREATING BACKENDS - Cause: {ex:?}")
                        });

                        b.ext.insert(Scheme::from(backend.scheme.clone()));

                        b
                    })
                    .collect::<Vec<Backend>>();

                let mut upstream = LoadBalancer::try_from_iter(backends).unwrap();

                let hc = pingora::lb::health_check::TcpHealthCheck::new();
                upstream.set_health_check(hc);
                upstream.health_check_frequency = Some(std::time::Duration::from_secs(1));

                ProxyType::LoadBalancer {
                    upstream: Upstream(Arc::new(upstream)),
                }
            }
        };

        if server.listen.http.is_some() {
            http_host_to_proxy_type.push((boxed_server_names.clone(), proxy_type.clone()));
        }

        if let Some(lib_config::Https {
            http2: server_http2,
            ssl_certificate,
            ssl_certificate_key,
            ..
        }) = server.listen.https
        {
            if server_http2 {
                http2 = true;
            }

            https_host_to_proxy_type.push((boxed_server_names.clone(), proxy_type));

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
        }
    }

    let pingora_http_server = PingoraHttpServer {
        ports: http_ports.into(),
        host_to_proxy_type: HostsToProxyType(http_host_to_proxy_type),
    };

    let pingora_https_server = PingoraHttpsServer {
        http2,
        ports: https_ports.into(),
        host_to_proxy_type: HostsToProxyType(https_host_to_proxy_type),
        host_to_certs: HostsToSslCert(host_to_certs),
    };

    Ok((pingora_http_server, pingora_https_server))
}
