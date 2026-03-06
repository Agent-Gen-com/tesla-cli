use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub region: Option<String>,
    pub vin: Option<String>,
    /// AgentGen subdomain (e.g. "abc123.agent-gen.com")
    pub domain: Option<String>,
    /// AgentGen origin ID
    pub origin_id: Option<String>,
    pub agentgen_api_key: Option<String>,
}

impl Config {
    pub fn config_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/tescmd")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn token_path() -> PathBuf {
        Self::config_dir().join("token.json")
    }

    pub fn keys_dir() -> PathBuf {
        Self::config_dir().join("keys")
    }

    pub fn private_key_path() -> PathBuf {
        Self::keys_dir().join("private.pem")
    }

    pub fn public_key_path() -> PathBuf {
        Self::keys_dir().join("public.pem")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Reading config from {}", path.display()))?;
        toml::from_str(&content).context("Parsing config.toml")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        std::fs::create_dir_all(path.parent().unwrap())?;
        let content = toml::to_string_pretty(self).context("Serializing config")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Writing config to {}", path.display()))
    }

    pub fn region(&self) -> &str {
        self.region.as_deref().unwrap_or("na")
    }

    pub fn base_url(&self) -> &str {
        match self.region() {
            "eu" => "https://fleet-api.prd.eu.vn.cloud.tesla.com",
            "cn" => "https://fleet-api.prd.cn.vn.cloud.tesla.com",
            _ => "https://fleet-api.prd.na.vn.cloud.tesla.com",
        }
    }

    /// Load a valid (non-expired) access token, refreshing if needed.
    pub async fn access_token(&self) -> Result<String> {
        let mut token = TokenData::load()?;
        if token.is_expired() {
            let client_id = self
                .client_id
                .as_deref()
                .context("client_id not configured — run 'tescmd setup'")?;
            let secret = self.client_secret.as_deref();
            token = crate::auth::refresh(&token, client_id, secret).await?;
            token.save()?;
        }
        Ok(token.access_token)
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp (seconds) when the token expires
    pub expires_at: f64,
}

impl TokenData {
    pub fn load() -> Result<Self> {
        let path = Config::token_path();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Reading token from {} — run 'tescmd setup' to authenticate", path.display()))?;
        serde_json::from_str(&content).context("Parsing token.json")
    }

    pub fn save(&self) -> Result<()> {
        let path = Config::token_path();
        std::fs::create_dir_all(path.parent().unwrap())?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)
            .with_context(|| format!("Writing token to {}", path.display()))
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        now >= self.expires_at - 60.0
    }
}
