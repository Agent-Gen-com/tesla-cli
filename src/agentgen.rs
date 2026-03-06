use anyhow::{Context, Result};

const AGENTGEN_BASE_URL: &str = "https://www.agent-gen.com/api/v1";

/// Provision a new origin subdomain.
/// Returns `(origin_id, domain)` where domain is e.g. `"abc123.agent-gen.com"`.
pub async fn provision_origin(api_key: &str) -> Result<(String, String)> {
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{}/origin", AGENTGEN_BASE_URL))
        .header("X-API-Key", api_key)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("AgentGen provision failed ({}): {}", resp.status(), resp.text().await?);
    }
    let data: serde_json::Value = resp.json().await?;
    let id = data["id"].as_str().context("Missing 'id' in AgentGen response")?.to_string();
    let origin = data["origin"]
        .as_str()
        .context("Missing 'origin' in AgentGen response")?
        .to_string();
    // origin = "https://abc123.agent-gen.com" → domain = "abc123.agent-gen.com"
    let domain = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();
    Ok((id, domain))
}

/// Upload the SPKI PEM public key to the given origin.
pub async fn upload_public_key(api_key: &str, origin_id: &str, pem: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{}/origin/{}/public-key", AGENTGEN_BASE_URL, origin_id))
        .header("X-API-Key", api_key)
        .header("Content-Type", "text/plain")
        .body(pem.to_string())
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("AgentGen public-key upload failed ({}): {}", resp.status(), resp.text().await?);
    }
    Ok(())
}
