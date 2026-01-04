use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::utils::{NonEmptyTrimedStr, Port, first_non_unique_ref};

pub type Sni = NonEmptyTrimedStr;

#[derive(
    Clone, Copy, Debug, Default, Deserialize, PartialEq, PartialOrd, strum_macros::EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    #[default]
    Http,
    Https,
}

/// [https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Redirections]
#[allow(unused)]
#[derive(Clone, Copy, Debug, Default, Deserialize, strum_macros::EnumString)]
pub enum RedirectionType {
    /// Permanent redirections: 301, Moved Permanently
    #[default]
    MovedPermanently = 301,
    /// Permanent redirections: 301, Permanent Redirect
    PermanentRedirect = 308,

    /// Temporary redirections: 301, Found
    Found = 302,
    /// Temporary redirections: 301, See Other
    SeeOther = 303,
    /// Temporary redirections: 301, Temporary Redirect
    TemporaryRedirect = 307,

    /// Special redirections: 300, Multiple Choices
    MultipleChoices = 300,

    /// Special redirections: 304, Not Modified
    NotModified = 304,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error, strum_macros::Display)]
pub enum LoadBalancerError {
    #[strum(to_string = "NameNotUnique:: Name: {0}")]
    NameNotUnique(Box<str>),

    AtleastOneBackend,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error, strum_macros::Display)]
pub enum ServerError {
    AtLeastOne,

    #[strum(to_string = "NameNotUnique:: Name: {0}")]
    NameNotUnique(Box<str>),

    #[strum(to_string = "NoServerType:: Name: {0}")]
    NoServerType(Box<str>),

    #[strum(to_string = "BothProxyAndLoadBalancing:: Name: {0}")]
    ServerTypeBothProxyAndLoadBalancing(Box<str>),

    #[strum(to_string = "HttpPortNotUniquePerServer:: Name: {0}, port: {1} ")]
    HttpPortNotUniquePerServer(Box<str>, u16),

    #[strum(to_string = "HttpsPortNotUniquePerServer:: Name: {0}, port: {1} ")]
    HttpsPortNotUniquePerServer(Box<str>, u16),

    #[strum(to_string = "BothAsHttpAndHttpsPort:: Port(s): {0:?}")]
    BothAsHttpAndHttpsPort(Vec<Port>),

    #[strum(to_string = "NoListeningPort:: Name: {0}")]
    NoListeningPort(Box<str>),

    #[strum(to_string = "UnknownLoadBalancer:: Name: {0}, LoadBalancerName: {1}")]
    UnknownLoadBalancer(Box<str>, Box<str>),
}

#[derive(Debug, Clone, PartialEq, thiserror::Error, strum_macros::Display)]
pub enum Error {
    Deserialize(#[from] toml::de::Error),
    LoadBalancer(#[from] LoadBalancerError),
    Server(#[from] ServerError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Config {
    #[serde(default)]
    load_balancer: Vec<LoadBalancer>,
    #[serde(default)]
    server: Vec<Server>,
}

impl Config {
    pub fn load_balancers(&self) -> &[LoadBalancer] {
        &self.load_balancer
    }

    pub fn servers(&self) -> &[Server] {
        &self.server
    }

    pub fn load_from_toml_str(toml: &str) -> Result<Self> {
        let config: Self = toml::from_str(toml).map_err(Error::Deserialize)?;

        config.verify()?;

        Ok(config)
    }

    pub fn load_from_path<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file_content =
            std::fs::read_to_string(path).expect("Should have been able to read the config file");

        Self::load_from_toml_str(&file_content)
    }

    pub fn verify(&self) -> Result<()> {
        self.verify_load_balancer()?;
        self.verify_server()?;

        Ok(())
    }

    fn verify_load_balancer(&self) -> Result<()> {
        //// At least on backend per load balancer
        let backend_lengths = self
            .load_balancer
            .iter()
            .map(|v| v.backend.len())
            .collect::<Vec<usize>>();
        if backend_lengths.contains(&0) {
            return Err(Error::LoadBalancer(LoadBalancerError::AtleastOneBackend));
        };

        //// Unique load balancer name
        let non_unique_load_balancer_name =
            first_non_unique_ref(self.load_balancer.iter().map(|v| v.name.as_ref()));

        if let Some(name) = non_unique_load_balancer_name {
            return Err(Error::LoadBalancer(LoadBalancerError::NameNotUnique(
                name.into(),
            )));
        };

        Ok(())
    }

    fn verify_server(&self) -> Result<()> {
        if self.server.is_empty() {
            return Err(Error::Server(ServerError::AtLeastOne));
        }

        //// Unique server names
        let non_unique_server_names =
            first_non_unique_ref(self.server.iter().map(|v| v.name.as_ref()));
        if let Some(name) = non_unique_server_names {
            return Err(Error::Server(ServerError::NameNotUnique(name.into())));
        };

        //// No server type
        for server in self.server.iter() {
            if server.load_balancer_name.is_none() && server.proxy.is_none() {
                return Err(Error::Server(ServerError::NoServerType(
                    server.name.as_ref().into(),
                )));
            }
        }

        //// No server type
        for server in self.server.iter() {
            if server.load_balancer_name.is_some() && server.proxy.is_some() {
                return Err(Error::Server(
                    ServerError::ServerTypeBothProxyAndLoadBalancing(server.name.as_ref().into()),
                ));
            }
        }

        //// No listening port
        for server in self.server.iter() {
            if server.http.is_empty() && server.https.is_empty() {
                return Err(Error::Server(ServerError::NoListeningPort(
                    server.name.as_ref().into(),
                )));
            }
        }

        // tracing::warn!(
        //     "server_name: {} not listening on any port, try adding http or https attribute",
        //     v.name
        // );

        //// server http listen port not unique
        for server in self.server.iter() {
            let non_unique_port = first_non_unique_ref(server.http.iter().map(|t| &t.listen_port));

            if let Some(port) = non_unique_port {
                return Err(Error::Server(ServerError::HttpPortNotUniquePerServer(
                    server.name.as_ref().into(),
                    **port,
                )));
            };
        }

        //// server https listen port not unique
        for server in self.server.iter() {
            let non_unique_port = first_non_unique_ref(server.https.iter().map(|t| &t.listen_port));

            if let Some(port) = non_unique_port {
                return Err(Error::Server(ServerError::HttpsPortNotUniquePerServer(
                    server.name.as_ref().into(),
                    **port,
                )));
            };
        }

        //// server common http https port
        let http_ports = self
            .server
            .iter()
            .flat_map(|v| v.http.iter().map(|t| t.listen_port))
            .collect::<HashSet<Port>>();

        let https_ports = self
            .server
            .iter()
            .flat_map(|v| v.https.iter().map(|t| t.listen_port))
            .collect::<HashSet<Port>>();

        let common_btw_http_and_https = http_ports
            .intersection(&https_ports)
            .copied()
            .collect::<Vec<Port>>();

        if !common_btw_http_and_https.is_empty() {
            return Err(Error::Server(ServerError::BothAsHttpAndHttpsPort(
                common_btw_http_and_https,
            )));
        }

        //// server unknown load balancer name
        let unique_load_balancer_names = self
            .load_balancer
            .iter()
            .map(|v| &v.name)
            .collect::<HashSet<&NonEmptyTrimedStr>>();

        for server in self.server.iter() {
            if let Some(load_balancer_name) = server.load_balancer_name.as_ref()
                && !unique_load_balancer_names.contains(load_balancer_name)
            {
                return Err(Error::Server(ServerError::UnknownLoadBalancer(
                    server.name.clone().into(),
                    server
                        .load_balancer_name
                        .clone()
                        .expect("load_balancer_name should have been present")
                        .into(),
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct LoadBalancer {
    pub(crate) name: NonEmptyTrimedStr,
    pub(crate) backend: Vec<BackendConfig>,
}

fn default_usize_1() -> usize {
    1
}
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct BackendConfig {
    #[serde(default)]
    pub(crate) scheme: Scheme,
    pub(crate) address: SocketAddr,
    #[serde(default = "default_usize_1")]
    pub(crate) weight: usize,

    /// Required when protocol::HTTPS
    pub(crate) sni: Option<Sni>,
}

fn default_true() -> bool {
    true
}
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Server {
    #[serde(default = "default_true")]
    pub(crate) enable: bool,
    pub(crate) name: NonEmptyTrimedStr,

    #[serde(default)]
    pub(crate) http: Vec<Http>,
    #[serde(default)]
    pub(crate) https: Vec<Https>,

    pub(crate) proxy: Option<Proxy>,
    pub(crate) load_balancer_name: Option<NonEmptyTrimedStr>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Http {
    pub(crate) listen_port: Port,
    // pub(crate) redirect: Option<RedirectConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Https {
    pub(crate) listen_port: Port,
    // pub(crate) redirect: Option<RedirectConfig>,
    #[serde(default)]
    pub(crate) http2: bool,

    pub(crate) ssl_certificate: PathBuf,
    pub(crate) ssl_certificate_key: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Proxy {
    #[serde(default)]
    pub(crate) scheme: Scheme,
    pub(crate) address: SocketAddr,

    /// Required when protocol::Https
    pub(crate) sni: Option<Sni>,
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{Config, Error, LoadBalancerError, ServerError},
        utils::Port,
    };

    #[test]
    fn loadbalancer_name_unique() {
        const CONFIG: &str = r#"
            [[load_balancer]]
            name = "backend 1 "

            [[load_balancer.backend]]
            address = "127.0.0.1:3059"

            [[load_balancer]]
            name = "backend 1 "

            [[load_balancer.backend]]
            address = "127.0.0.1:3059"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::LoadBalancer(LoadBalancerError::NameNotUnique(Box::from("backend 1")))
        )
    }

    #[test]
    fn loadbalancer_name_not_empty() {
        const CONFIG: &str = r#"
            [[load_balancer]]
            name = "backend 1"

            [[load_balancer.backend]]
            address = "127.0.0.1:3059"

            [[load_balancer]]
            name = "  "

            [[load_balancer.backend]]
            address = "127.0.0.1:3059"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        if let Error::Deserialize(_) = config.unwrap_err() {
        } else {
            panic!("Error not of type Error::Deserialize")
        }
    }

    #[test]
    fn loadbalancer_atleast_one_backend() {
        const CONFIG: &str = r#"
            [[load_balancer]]
            name = "backend 1"
            backend = []
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        if let Error::LoadBalancer(LoadBalancerError::AtleastOneBackend) = config.unwrap_err() {
        } else {
            panic!("Error not of type Error::LoadBalancer(LoadBalancerError::BackendEmpty)")
        }
    }

    #[test]
    fn server_atleast_one() {
        const CONFIG: &str = r#"
            server = []
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        if let Error::Server(ServerError::AtLeastOne) = config.unwrap_err() {
        } else {
            panic!("Error not of type Error::Server(ServerError::AtLeastOne)")
        }
    }

    #[test]
    fn server_at_least_one() {
        const CONFIG: &str = r#""#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(config.unwrap_err(), Error::Server(ServerError::AtLeastOne))
    }

    #[test]
    fn server_name_unique() {
        const CONFIG: &str = r#"
            [[server]]
            name = "abc.zennozenith.com"

            [[server]]
            name = "abc.zennozenith.com"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::Server(ServerError::NameNotUnique(Box::from("abc.zennozenith.com")))
        )
    }

    #[test]
    fn server_name_not_empty() {
        const CONFIG: &str = r#"
            [[server]]
            name = "  "
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        if let Error::Deserialize(_) = config.unwrap_err() {
        } else {
            panic!("Error not of type Error::Deserialize")
        }
    }

    #[test]
    fn server_no_server_type() {
        const CONFIG: &str = r#"
            [[server]]
            name = "example.com"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::Server(ServerError::NoServerType(Box::from("example.com")))
        )
    }

    #[test]
    fn server_server_type_both_proxy_load_balancing() {
        const CONFIG: &str = r#"
            [[load_balancer]]
            name = "backend 1  "

            [[load_balancer.backend]]
            address = "127.0.0.1:3060"

            [[server]]
            name = "example.com"
            load_balancer_name = "backend 1  "

            [[server.http]]
            listen_port = 6188

            [server.proxy]
            address = "127.0.0.1:8096"
            host = "127.0.0.1"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::Server(ServerError::ServerTypeBothProxyAndLoadBalancing(Box::from(
                "example.com"
            )))
        )
    }

    #[test]
    fn server_no_listening_port() {
        const CONFIG: &str = r#"
            [[server]]
            name = "example.com"

            [server.proxy]
            address = "127.0.0.1:8096"
            host = "127.0.0.1"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::Server(ServerError::NoListeningPort(Box::from("example.com")))
        )
    }

    #[test]
    fn server_disjoint_http_https_port() {
        const CONFIG: &str = r#"
            [[server]]
            name = "example.com"

            [[server.http]]
            listen_port = 6188

            [[server.https]]
            listen_port = 6188
            http2 = true
            ssl_certificate = "tests/keys/abc.zennozenith.com/server.crt"
            ssl_certificate_key = "tests/keys/abc.zennozenith.com/key.pem"

            [server.proxy]
            address = "127.0.0.1:8096"
            host = "127.0.0.1"
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::Server(ServerError::BothAsHttpAndHttpsPort(vec![Port::from(6188)]))
        )
    }

    #[test]
    fn server_unknown_load_balancer_name() {
        const CONFIG: &str = r#"
            [[server]]
            name = "example.com"

            [[server.http]]
            listen_port = 6188

            [server.proxy]
            address = "127.0.0.1:8096"
            host = "127.0.0.1"

            [[server]]
            name = "abc.example.com"
            load_balancer_name = "backend 1"

            [[server.http]]
            listen_port = 6188
        "#;

        let config = Config::load_from_toml_str(CONFIG);

        assert!(config.is_err(), "Config did not error");
        assert_eq!(
            config.unwrap_err(),
            Error::Server(ServerError::UnknownLoadBalancer(
                Box::from("abc.example.com"),
                Box::from("backend 1")
            ))
        )
    }
}
