use anyhow::{Context, Result};
use std::io::{self, Write};

use crate::{agentgen, auth, config::Config, crypto};

fn prompt(label: &str) -> String {
    print!("{}: ", label);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn prompt_default(label: &str, default: &str) -> String {
    print!("{} [{}]: ", label, default);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

pub async fn run() -> Result<()> {
    println!("\n=== tescmd setup ===\n");
    println!("This wizard configures tescmd for use with the Tesla Fleet API.");
    println!("AgentGen replaces GitHub Pages / Tailscale for public-key hosting.\n");

    let mut config = Config::load()?;

    // ------------------------------------------------------------------
    // Step 1 — AgentGen API key → provision origin
    // ------------------------------------------------------------------
    println!("--- Step 1/5: AgentGen origin ---");
    println!("AgentGen hosts your Tesla public key at a stable HTTPS URL.");
    println!("Get a free API key at https://www.agent-gen.com\n");

    let api_key = prompt("AgentGen API key");
    if api_key.is_empty() {
        anyhow::bail!("AgentGen API key is required");
    }

    print!("  Provisioning origin... ");
    io::stdout().flush().unwrap();
    let (origin_id, domain) = agentgen::provision_origin(&api_key).await?;
    println!("done.");
    println!("  Domain: {}", domain);

    config.agentgen_api_key = Some(api_key.clone());
    config.origin_id = Some(origin_id.clone());
    config.domain = Some(domain.clone());

    // ------------------------------------------------------------------
    // Step 2 — Tesla Developer App credentials
    // ------------------------------------------------------------------
    println!("\n--- Step 2/5: Tesla Developer App ---");
    println!("Register your app at https://developer.tesla.com");
    println!();
    println!("  1. Application name   — pick any name");
    println!("  2. Description        — any description");
    println!("  3. Purpose of usage   — \"Personal use with my own Tesla\"");
    println!("  4. Allowed Origin URL — https://{}", domain);
    println!("  5. OAuth redirect URI — http://localhost:13227/callback");
    println!("  6. API & Scopes       — select all (or choose specific scopes)");
    println!("  7. Billing details    — choose Skip & Submit");
    println!();

    let client_id = prompt("Tesla Client ID");
    if client_id.is_empty() {
        anyhow::bail!("Client ID is required");
    }
    let client_secret = prompt("Tesla Client Secret (press Enter to skip)");
    let region = prompt_default("Region (na / eu / cn)", "na");

    config.client_id = Some(client_id.clone());
    config.client_secret = if client_secret.is_empty() {
        None
    } else {
        Some(client_secret.clone())
    };
    config.region = Some(region.clone());

    // ------------------------------------------------------------------
    // Step 3 — EC key pair generation + upload to AgentGen
    // (must happen before partner registration — Tesla fetches the key
    //  when you call POST /api/1/partner_accounts)
    // ------------------------------------------------------------------
    println!("\n--- Step 3/5: EC key pair ---");
    print!("  Generating P-256 key pair... ");
    io::stdout().flush().unwrap();

    let (private_pem, public_pem) = crypto::generate_key_pair()?;
    println!("done.");

    // Save keys
    let keys_dir = Config::keys_dir();
    std::fs::create_dir_all(&keys_dir)?;
    std::fs::write(Config::private_key_path(), &private_pem)
        .context("Writing private key")?;
    std::fs::write(Config::public_key_path(), &public_pem)
        .context("Writing public key")?;

    // Set restrictive permissions on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(Config::private_key_path(), std::fs::Permissions::from_mode(0o600))?;
    }

    println!("  Private key: {}", Config::private_key_path().display());
    println!("  Public key:  {}", Config::public_key_path().display());

    // Upload public key to AgentGen (must be live before partner registration)
    print!("  Uploading public key to AgentGen... ");
    io::stdout().flush().unwrap();
    agentgen::upload_public_key(&api_key, &origin_id, &public_pem).await?;
    println!("done.");
    println!(
        "  Key live at: https://{}/.well-known/appspecific/com.tesla.3p.public-key.pem",
        domain
    );

    // ------------------------------------------------------------------
    // Step 4 — Partner registration
    // (Tesla fetches the public key URL during this call — must come after upload)
    // ------------------------------------------------------------------
    println!("\n--- Step 4/5: Partner registration ---");
    print!("  Registering partner account with Tesla Fleet API... ");
    io::stdout().flush().unwrap();

    let secret = config.client_secret.as_deref();
    if let Some(s) = secret {
        auth::register_partner(&client_id, s, &domain, &region).await?;
        println!("done.");
    } else {
        println!("\n  (Skipped — no client secret provided. Partner commands may not work.)");
    }

    // ------------------------------------------------------------------
    // Step 5 — OAuth login + virtual key enrollment
    // ------------------------------------------------------------------
    println!("\n--- Step 5/5: OAuth login + virtual key enrollment ---");
    let token = auth::login(&client_id, secret, &region).await?;
    token.save()?;
    println!("  Token saved.");

    // Virtual key enrollment (open after OAuth so the Tesla app session is fresh)
    let enrollment_url = format!("https://tesla.com/_ak/{}", domain);
    println!("\n  Opening Tesla virtual key enrollment:");
    println!("    {}", enrollment_url);
    println!("  Approve the key in your Tesla app when prompted.\n");
    if open::that(&enrollment_url).is_err() {
        println!("  (Could not open browser — please open the URL above manually.)");
    }
    prompt("  Press Enter after approving the key in the Tesla app");

    // ------------------------------------------------------------------
    // Save config
    // ------------------------------------------------------------------
    config.save()?;
    println!("\n=== Setup complete! ===");
    println!("Config: {}", Config::config_path().display());
    println!("Token:  {}", Config::token_path().display());
    println!("\nTry: tescmd vehicle list");

    Ok(())
}
