use anyhow::{Context, Result};
use std::time::Duration;

use crate::config::Config;

pub struct TeslaClient {
    http: reqwest::Client,
    pub config: Config,
}

impl TeslaClient {
    pub fn new(config: Config) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("HTTP client");
        Self { http, config }
    }

    async fn token(&self) -> Result<String> {
        self.config.access_token().await
    }

    // ------------------------------------------------------------------
    // Vehicle list / data / wake
    // ------------------------------------------------------------------

    pub async fn list_vehicles(&self) -> Result<Vec<serde_json::Value>> {
        let token = self.token().await?;
        let resp = self
            .http
            .get(format!("{}/api/1/vehicles", self.config.base_url()))
            .bearer_auth(&token)
            .send()
            .await?;
        let resp = check_status(resp).await?;
        let data: serde_json::Value = resp.json().await?;
        Ok(data["response"].as_array().cloned().unwrap_or_default())
    }

    pub async fn vehicle_data(&self, vin: &str) -> Result<serde_json::Value> {
        let token = self.token().await?;
        let resp = self
            .http
            .get(format!("{}/api/1/vehicles/{}/vehicle_data", self.config.base_url(), vin))
            .bearer_auth(&token)
            .send()
            .await?;
        let resp = check_status(resp).await?;
        let data: serde_json::Value = resp.json().await?;
        Ok(data["response"].clone())
    }

    pub async fn wake_vehicle(&self, vin: &str) -> Result<serde_json::Value> {
        let token = self.token().await?;
        let resp = self
            .http
            .post(format!("{}/api/1/vehicles/{}/wake_up", self.config.base_url(), vin))
            .bearer_auth(&token)
            .send()
            .await?;
        let resp = check_status(resp).await?;
        let data: serde_json::Value = resp.json().await?;
        Ok(data["response"].clone())
    }

    // ------------------------------------------------------------------
    // VIN resolution
    // ------------------------------------------------------------------

    /// Return the VIN from CLI arg, config, or auto-select first vehicle.
    pub async fn resolve_vin(&self, vin_arg: Option<&str>) -> Result<String> {
        if let Some(v) = vin_arg {
            return Ok(v.to_string());
        }
        if let Some(v) = &self.config.vin {
            return Ok(v.clone());
        }
        let vehicles = self.list_vehicles().await?;
        let first = vehicles
            .first()
            .context("No vehicles found on this account")?;
        first["vin"]
            .as_str()
            .context("Vehicle has no VIN field")
            .map(str::to_string)
    }
}

async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Tesla API returned HTTP {}: {}", status, body);
    }
    Ok(resp)
}
