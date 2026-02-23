use serde::Deserialize;
use std::fs;
use std::path::Path;
use tracing::{info, error};

#[derive(Debug, Deserialize, Clone)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub upstreams: Vec<UpstreamConfig>,
    pub rules: RulesConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub cache_capacity: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub address: String,
    pub protocol: String, // udp tcp doh
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulesConfig {
    pub enable_cache: bool,
    pub block_mode: String,
    pub blacklist: Vec<String>,
}

impl GatewayConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path_ref = path.as_ref();
        info!("Loading config {:?}", path_ref);
        
        let config_content = match fs::read_to_string(path_ref) {
            Ok(content) => content,
            Err(e) => {
                error!("Failed {}", e);
                return Err(e.into());
            }
        };

        let config: GatewayConfig = match toml::from_str(&config_content) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed {}", e);
                return Err(e.into());
            }
        };

        info!("config loaded {}", config.upstreams.len());
        Ok(config)
    }
}