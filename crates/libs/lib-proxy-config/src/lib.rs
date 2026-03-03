use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU16,
    path::{Path, PathBuf},
};

use serde::Deserialize;

mod util;

use url::Url;
pub use util::RedirectHttpCode;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("config (toml) deserialize err: {0:?}")]
    Deserialize(Box<str>),
    // Deserialize(#[from] toml::de::Error),
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
    // #[serde(flatten)]
    pub kind: ServerType,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
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
#[serde(rename_all = "lowercase")]
pub enum ServerType {
    Proxy(ProxyType),
    Redirect(Redirect),
    Custom(Custom),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Custom {
    pub http_code: u16,
    pub content: Option<Content>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum Content {
    Text(String),
    Bytes(Box<[u8]>),

    Path {
        path: PathBuf,
        #[serde(default)]
        cache: bool,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct Redirect {
    pub http_code: RedirectHttpCode,
    #[serde(default)]
    pub preserve_path: bool,
    pub location: Url,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Direct {
        scheme: Scheme,
        address: SocketAddr,
    },
    LoadBalanced {
        alg: LoadBalancingAlgo,
        backend: Vec<Backend>,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub enum LoadBalancingAlgo {
    RoundRobin,
}

fn default_weight() -> NonZeroU16 {
    NonZeroU16::new(1).expect("NonZeroU16 cannot be zero")
}

#[derive(Clone, Debug, Deserialize)]
pub struct Backend {
    #[serde(default = "default_weight")]
    pub weight: NonZeroU16,
    pub address: SocketAddr,
    pub scheme: Scheme,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https {
        #[serde(default)]
        sni: String,
    },
}

impl Config {
    pub fn load_from_toml_str(toml: &str) -> Result<Self> {
        toml::from_str(toml).map_err(|e| Error::Deserialize(e.to_string().into()))
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

    const CONFIG_FIXTURE: &str = include_str!("../../../../examples/config.toml");

    #[test]
    fn valid_example_config() {
        let config = Config::load_from_toml_str(CONFIG_FIXTURE);
        assert!(config.is_ok(), "Config Error {config:?}");
        // dbg!(config.unwrap());
    }
}
