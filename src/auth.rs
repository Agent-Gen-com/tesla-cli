use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use crate::config::TokenData;

const AUTHORIZE_URL: &str = "https://auth.tesla.com/oauth2/v3/authorize";
const TOKEN_URL: &str = "https://auth.tesla.com/oauth2/v3/token";
const CALLBACK_PORT: u16 = 13227;
const REDIRECT_URI: &str = "http://localhost:13227/callback";
const SCOPES: &str = "openid offline_access vehicle_device_data vehicle_cmds vehicle_charging_cmds vehicle_location";

fn generate_code_verifier() -> String {
    let bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(96)
        .collect();
    let b64 = URL_SAFE_NO_PAD.encode(&bytes);
    b64[..128].to_string()
}

fn generate_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest)
}

fn generate_state() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Spawn a local HTTP server, wait for the OAuth redirect, return (code, state).
fn wait_for_callback() -> Result<(String, String)> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", CALLBACK_PORT))
        .with_context(|| format!("Could not bind to port {}", CALLBACK_PORT))?;

    let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();

    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let mut request_line = String::new();
            {
                let mut reader = BufReader::new(&stream);
                let _ = reader.read_line(&mut request_line);
            }

            // "GET /callback?code=xxx&state=yyy HTTP/1.1"
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();

            let maybe_result = path.split('?').nth(1).and_then(|query| {
                let mut code = None;
                let mut state = None;
                for kv in query.split('&') {
                    let mut parts = kv.splitn(2, '=');
                    let k = parts.next().unwrap_or("");
                    let v = parts
                        .next()
                        .and_then(|s| urlencoding::decode(s).ok())
                        .map(|c| c.into_owned())
                        .unwrap_or_default();
                    if k == "code" {
                        code = Some(v);
                    } else if k == "state" {
                        state = Some(v);
                    }
                }
                code.zip(state)
            });

            let body = if maybe_result.is_some() {
                "<h1>Authentication successful! You can close this window.</h1>"
            } else {
                "<h1>Authentication failed — no code received.</h1>"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = (&stream).write_all(response.as_bytes());

            if let Some(pair) = maybe_result {
                let _ = tx.send(pair);
            }
        }
    });

    rx.recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|_| anyhow::anyhow!("OAuth callback timed out after 120 seconds"))
}

/// Full PKCE login flow — opens browser, waits for callback, exchanges code.
pub async fn login(client_id: &str, client_secret: Option<&str>, _region: &str) -> Result<TokenData> {
    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);
    let state = generate_state();

    let params: Vec<(&str, String)> = vec![
        ("response_type", "code".into()),
        ("client_id", client_id.into()),
        ("redirect_uri", REDIRECT_URI.into()),
        ("scope", SCOPES.into()),
        ("state", state.clone()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".into()),
    ];
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let auth_url = format!("{}?{}", AUTHORIZE_URL, query);

    println!("\nOpen this URL in your browser to authenticate:");
    println!("  {}\n", auth_url);
    if open::that(&auth_url).is_err() {
        println!("(Could not open browser automatically — please paste the URL above.)");
    }
    println!("Waiting for OAuth callback on port {}...", CALLBACK_PORT);

    let (code, returned_state) = tokio::task::spawn_blocking(wait_for_callback).await??;

    if returned_state != state {
        anyhow::bail!("OAuth state mismatch — possible CSRF attack");
    }

    exchange_code(&code, &verifier, client_id, client_secret).await
}

async fn exchange_code(
    code: &str,
    verifier: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<TokenData> {
    let http = reqwest::Client::new();
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("code_verifier", verifier.to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", REDIRECT_URI.to_string()),
    ];
    if let Some(s) = client_secret {
        form.push(("client_secret", s.to_string()));
    }
    let resp = http.post(TOKEN_URL).form(&form).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Token exchange failed: {}", resp.text().await?);
    }
    parse_token_response(resp).await
}

/// Refresh an expired access token using the refresh token.
pub async fn refresh(
    token: &TokenData,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<TokenData> {
    let refresh_tok = token
        .refresh_token
        .as_deref()
        .context("No refresh token available — run 'teslacli setup' to re-authenticate")?;
    let http = reqwest::Client::new();
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_tok.to_string()),
        ("client_id", client_id.to_string()),
    ];
    if let Some(s) = client_secret {
        form.push(("client_secret", s.to_string()));
    }
    let resp = http.post(TOKEN_URL).form(&form).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Token refresh failed: {}", resp.text().await?);
    }
    let mut new_token = parse_token_response(resp).await?;
    // Preserve old refresh token if not rotated
    if new_token.refresh_token.is_none() {
        new_token.refresh_token = token.refresh_token.clone();
    }
    Ok(new_token)
}

async fn parse_token_response(resp: reqwest::Response) -> Result<TokenData> {
    let data: serde_json::Value = resp.json().await?;
    let expires_in = data["expires_in"].as_f64().unwrap_or(3600.0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    Ok(TokenData {
        access_token: data["access_token"]
            .as_str()
            .context("Missing access_token")?
            .to_string(),
        refresh_token: data["refresh_token"].as_str().map(str::to_string),
        expires_at: now + expires_in,
    })
}

// ---------------------------------------------------------------------------
// Partner registration
// ---------------------------------------------------------------------------

fn fleet_base_url(region: &str) -> &'static str {
    match region {
        "eu" => "https://fleet-api.prd.eu.vn.cloud.tesla.com",
        "cn" => "https://fleet-api.prd.cn.vn.cloud.tesla.com",
        _ => "https://fleet-api.prd.na.vn.cloud.tesla.com",
    }
}

pub async fn get_partner_token(client_id: &str, client_secret: &str, region: &str) -> Result<String> {
    let audience = fleet_base_url(region);
    let http = reqwest::Client::new();
    let form = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id.to_string()),
        ("client_secret", client_secret.to_string()),
        ("scope", "openid vehicle_device_data vehicle_cmds vehicle_charging_cmds vehicle_location energy_device_data energy_cmds user_data".to_string()),
        ("audience", audience.to_string()),
    ];
    let resp = http.post(TOKEN_URL).form(&form).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Partner token request failed: {}", resp.text().await?);
    }
    let data: serde_json::Value = resp.json().await?;
    data["access_token"]
        .as_str()
        .context("Missing access_token")
        .map(str::to_string)
}

pub async fn register_partner(
    client_id: &str,
    client_secret: &str,
    domain: &str,
    region: &str,
) -> Result<()> {
    let partner_token = get_partner_token(client_id, client_secret, region).await?;
    let base_url = fleet_base_url(region);
    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{}/api/1/partner_accounts", base_url))
        .bearer_auth(&partner_token)
        .json(&serde_json::json!({ "domain": domain }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let text = resp.text().await?;
        if text.contains("already been taken") {
            return Ok(());
        }
        anyhow::bail!("Partner registration failed: {}", text);
    }
    Ok(())
}
