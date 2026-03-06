//! Vehicle Command Protocol (VCP) client.
//! Implements ECDH session establishment and HMAC-signed command dispatch.

pub mod commands;
pub mod metadata;
pub mod proto;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use p256::SecretKey;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use commands::Command;
use proto::{
    decode_field, encode_bytes_field, encode_fixed32_field, encode_varint_field, FieldValue,
};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct Session {
    epoch: Vec<u8>,
    counter: u32,
    signing_key: [u8; 32],
    /// Wall-clock time (Unix seconds) when the vehicle's epoch counter was 0.
    time_zero: f64,
    created_at: Instant,
}

impl Session {
    const TTL: Duration = Duration::from_secs(300);

    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Self::TTL
    }

    fn next_counter(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }

    /// expires_at in vehicle-relative seconds: now + 15 - time_zero
    fn expires_at(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        (now + 15.0 - self.time_zero) as u32
    }
}

// ---------------------------------------------------------------------------
// Stale-session fault codes
// ---------------------------------------------------------------------------

/// Faults that indicate the session is stale and require a re-handshake.
fn is_stale_fault(fault: u32) -> bool {
    matches!(fault, 5 | 6 | 15 | 17)
}

// ---------------------------------------------------------------------------
// HMAC key derivation
// ---------------------------------------------------------------------------

fn derive_signing_key(session_key: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(session_key).expect("HMAC key len");
    mac.update(b"authenticated command");
    mac.finalize().into_bytes().into()
}

fn compute_hmac_tag(signing_key: &[u8], metadata_bytes: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC key len");
    mac.update(metadata_bytes);
    mac.update(&[0xFFu8]); // TAG_END separator between metadata and payload
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

// ---------------------------------------------------------------------------
// RoutableMessage builder helpers
// ---------------------------------------------------------------------------

/// Build a session-info-request RoutableMessage (for ECDH handshake).
fn build_handshake_request(domain: u8, client_pub: &[u8]) -> Vec<u8> {
    let rand_16: [u8; 16] = rand::random();
    let uuid: [u8; 16] = rand::random();

    // Destination { domain (field 1) }
    let to_dest = encode_varint_field(1, domain as u64);
    // Destination { routing_address (field 2) }
    let from_dest = encode_bytes_field(2, &rand_16);
    // SessionInfoRequest { public_key (field 1) }
    let sir = encode_bytes_field(1, client_pub);

    let mut msg = Vec::new();
    msg.extend(encode_bytes_field(6, &to_dest)); // to_destination
    msg.extend(encode_bytes_field(7, &from_dest)); // from_destination
    msg.extend(encode_bytes_field(14, &sir)); // session_info_request
    msg.extend(encode_bytes_field(51, &uuid)); // uuid
    msg
}

/// Build a signed command RoutableMessage.
fn build_signed_message(
    domain: u8,
    payload: &[u8],
    client_pub: &[u8],
    epoch: &[u8],
    counter: u32,
    expires_at: u32,
    hmac_tag: &[u8; 32],
) -> Vec<u8> {
    let rand_16: [u8; 16] = rand::random();
    let uuid: [u8; 16] = rand::random();

    // to_destination / from_destination
    let to_dest = encode_varint_field(1, domain as u64);
    let from_dest = encode_bytes_field(2, &rand_16);

    // KeyIdentity { public_key (field 1) }
    let key_identity = encode_bytes_field(1, client_pub);

    // HMACPersonalizedData { epoch(1), counter(2), expires_at(3, fixed32 LE), tag(4) }
    let mut hmac_data = Vec::new();
    hmac_data.extend(encode_bytes_field(1, epoch));
    hmac_data.extend(encode_varint_field(2, counter as u64));
    hmac_data.extend(encode_fixed32_field(3, expires_at));
    hmac_data.extend(encode_bytes_field(4, hmac_tag));

    // SignatureData { signer_identity(1), hmac_personalized_data(8) }
    let mut sig_data = Vec::new();
    sig_data.extend(encode_bytes_field(1, &key_identity));
    sig_data.extend(encode_bytes_field(8, &hmac_data));

    let mut msg = Vec::new();
    msg.extend(encode_bytes_field(6, &to_dest)); // to_destination
    msg.extend(encode_bytes_field(7, &from_dest)); // from_destination
    msg.extend(encode_bytes_field(10, payload)); // protobuf_message_as_bytes
    msg.extend(encode_bytes_field(13, &sig_data)); // signature_data
    msg.extend(encode_bytes_field(51, &uuid)); // uuid
    msg
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

struct SessionInfo {
    counter: u32,
    public_key: Vec<u8>,
    epoch: Vec<u8>,
    clock_time: u32,
}

fn parse_message_fault(data: &[u8]) -> u32 {
    let mut pos = 0;
    while pos < data.len() {
        if let Some((fn_, val, np)) = decode_field(data, pos) {
            if fn_ == 12 {
                if let FieldValue::Bytes(status_bytes) = val {
                    let mut spos = 0;
                    while spos < status_bytes.len() {
                        if let Some((sf, FieldValue::Varint(v), snew)) =
                            decode_field(&status_bytes, spos)
                        {
                            if sf == 2 {
                                return v as u32;
                            }
                            spos = snew;
                        } else {
                            break;
                        }
                    }
                }
            }
            pos = np;
        } else {
            break;
        }
    }
    0
}

fn parse_session_info_from_response(data: &[u8]) -> Result<(u32, SessionInfo)> {
    let fault = parse_message_fault(data);

    let mut session_info_bytes: Option<Vec<u8>> = None;
    let mut pos = 0;
    while pos < data.len() {
        if let Some((fn_, val, np)) = decode_field(data, pos) {
            if fn_ == 15 {
                if let FieldValue::Bytes(b) = val {
                    session_info_bytes = Some(b);
                }
            }
            pos = np;
        } else {
            break;
        }
    }

    if fault != 0 && session_info_bytes.is_none() {
        anyhow::bail!("Handshake fault {}: {}", fault, fault_description(fault));
    }

    let si_bytes = session_info_bytes.context("No session_info in handshake response")?;

    let mut si = SessionInfo {
        counter: 0,
        public_key: vec![],
        epoch: vec![],
        clock_time: 0,
    };
    let mut pos = 0;
    while pos < si_bytes.len() {
        if let Some((fn_, val, np)) = decode_field(&si_bytes, pos) {
            match (fn_, val) {
                (1, FieldValue::Varint(v)) => si.counter = v as u32,
                (2, FieldValue::Bytes(b)) => si.public_key = b,
                (3, FieldValue::Bytes(b)) => si.epoch = b,
                // Some vehicles encode clock_time as varint, others as fixed32.
                (4, FieldValue::Varint(v)) => si.clock_time = v as u32,
                (4, FieldValue::Fixed32(v)) => si.clock_time = v,
                _ => {}
            }
            pos = np;
        } else {
            break;
        }
    }

    Ok((fault, si))
}

fn fault_description(fault: u32) -> &'static str {
    match fault {
        0 => "OK",
        1 => "BUSY",
        2 => "TIMEOUT",
        3 => "UNKNOWN_KEY_ID — key not enrolled on vehicle",
        4 => "INACTIVE_KEY",
        5 => "INVALID_SIGNATURE",
        6 => "INVALID_TOKEN_OR_COUNTER",
        7 => "INSUFFICIENT_PRIVILEGES",
        9 => "INVALID_COMMAND",
        12 => "WRONG_PERSONALIZATION",
        15 => "INCORRECT_EPOCH",
        17 => "TIME_EXPIRED",
        _ => "unknown fault",
    }
}

// ---------------------------------------------------------------------------
// VcpClient
// ---------------------------------------------------------------------------

pub struct VcpClient {
    private_key: SecretKey,
    client_pub: Vec<u8>, // 65-byte uncompressed point
    sessions: HashMap<(String, u8), Session>,
}

impl VcpClient {
    /// Create from a PKCS#8 PEM private key string.
    pub fn new(private_key_pem: &str) -> Result<Self> {
        let secret = crate::crypto::load_private_key(private_key_pem)?;
        let client_pub = crate::crypto::uncompressed_public_key(&secret);
        Ok(Self {
            private_key: secret,
            client_pub,
            sessions: HashMap::new(),
        })
    }

    async fn do_handshake(
        &mut self,
        http: &reqwest::Client,
        base_url: &str,
        access_token: &str,
        vin: &str,
        domain: u8,
    ) -> Result<()> {
        let msg = build_handshake_request(domain, &self.client_pub);
        let encoded = STANDARD.encode(&msg);

        let resp = http
            .post(format!("{}/api/1/vehicles/{}/signed_command", base_url, vin))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "routable_message": encoded }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Handshake HTTP {}: {}", status, body);
        }

        let resp_data: serde_json::Value = resp.json().await?;
        let response_b64 = resp_data["response"]
            .as_str()
            .with_context(|| format!("No 'response' field in handshake response: {}", resp_data))?;
        let response_bytes = STANDARD.decode(response_b64).context("base64 decode")?;

        let (_fault, si) = parse_session_info_from_response(&response_bytes)?;

        if si.public_key.is_empty() {
            anyhow::bail!("No vehicle public key in session info for {}", vin);
        }

        let session_key = crate::crypto::derive_session_key(&self.private_key, &si.public_key)
            .context("ECDH key derivation")?;
        let signing_key = derive_signing_key(&session_key);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let time_zero = if si.clock_time > 0 {
            now - si.clock_time as f64
        } else {
            now
        };

        self.sessions.insert(
            (vin.to_string(), domain),
            Session {
                epoch: si.epoch,
                counter: si.counter,
                signing_key,
                time_zero,
                created_at: Instant::now(),
            },
        );
        Ok(())
    }

    async fn ensure_session(
        &mut self,
        http: &reqwest::Client,
        base_url: &str,
        access_token: &str,
        vin: &str,
        domain: u8,
    ) -> Result<()> {
        let key = (vin.to_string(), domain);
        let needs = match self.sessions.get(&key) {
            None => true,
            Some(s) => s.is_expired(),
        };
        if needs {
            self.sessions.remove(&key);
            self.do_handshake(http, base_url, access_token, vin, domain).await?;
        }
        Ok(())
    }

    /// Send a VCP command, establishing or reusing an ECDH session.
    /// Retries once on stale-session faults.
    pub async fn send_command(
        &mut self,
        http: &reqwest::Client,
        base_url: &str,
        access_token: &str,
        vin: &str,
        command: &Command,
    ) -> Result<()> {
        let domain = command.domain();
        let key = (vin.to_string(), domain);

        for attempt in 0u8..2 {
            self.ensure_session(http, base_url, access_token, vin, domain)
                .await?;

            let client_pub = self.client_pub.clone();
            let payload = command.build_payload();

            let (counter, expires_at, epoch, signing_key) = {
                let session = self.sessions.get_mut(&key).unwrap();
                let c = session.next_counter();
                let e = session.expires_at();
                let ep = session.epoch.clone();
                let sk = session.signing_key;
                (c, e, ep, sk)
            };

            let metadata_bytes =
                metadata::encode_metadata(&epoch, expires_at, counter, domain, vin);
            let hmac_tag = compute_hmac_tag(&signing_key, &metadata_bytes, &payload);
            let msg =
                build_signed_message(domain, &payload, &client_pub, &epoch, counter, expires_at, &hmac_tag);
            let encoded = STANDARD.encode(&msg);

            let resp = http
                .post(format!("{}/api/1/vehicles/{}/signed_command", base_url, vin))
                .bearer_auth(access_token)
                .json(&serde_json::json!({ "routable_message": encoded }))
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Command HTTP {}: {}", status, body);
            }

            let resp_data: serde_json::Value = resp.json().await?;
            let response_b64 = resp_data["response"]
                .as_str()
                .with_context(|| format!("No 'response' field in command response: {}", resp_data))?;
            let response_bytes = STANDARD.decode(response_b64).context("base64 decode")?;
            let fault = parse_message_fault(&response_bytes);

            match fault {
                0 => return Ok(()),
                f if is_stale_fault(f) && attempt == 0 => {
                    // Invalidate stale session and retry
                    self.sessions.remove(&key);
                    continue;
                }
                f => {
                    anyhow::bail!(
                        "Vehicle rejected command (fault {}): {}",
                        f,
                        fault_description(f)
                    );
                }
            }
        }

        anyhow::bail!("Command failed after session refresh")
    }
}
