use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("config (toml) deserialize err: {0:?}")]
    Deserialize(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub server: Vec<Server>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize)]
pub struct Server {
    #[serde(default = "default_true")]
    pub enable: bool,
    pub name: HashSet<String>,
    pub listen: Listen,
    pub proxy: ProxyType,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Listen {
    pub http: Option<Http>,
    pub https: Option<Https>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Http {
    pub port: HashSet<u16>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Https {
    pub port: HashSet<u16>,
    pub http2: bool,
    pub ssl_certificate: PathBuf,
    pub ssl_certificate_key: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ProxyType {
    LoadBalancer {
        alg: LoadBalancingAlgo,
        backend: Vec<Backend>,
    },
    Proxy {
        scheme: Scheme,
        address: SocketAddr,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub enum LoadBalancingAlgo {
    RoundRobin,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Backend {
    pub weight: u16,
    pub address: SocketAddr,
    pub scheme: Scheme,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https { sni: String },
}

impl Config {
    pub fn load_from_toml_str(toml: &str) -> Result<Self> {
        toml::from_str(toml).map_err(Error::Deserialize)
    }

    pub fn load_from_path<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file_content =
            std::fs::read_to_string(path).expect("Should have been able to read the config file");

        Self::load_from_toml_str(&file_content)
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    const CONFIG_FIXTURE: &str = include_str!("../../lib-proxy/examples/config.toml");

    #[test]
    fn valid_example_config() {
        let config = Config::load_from_toml_str(CONFIG_FIXTURE);
        assert!(config.is_ok(), "Config Error {config:?}");
    }
}
