mod agentgen;
mod api;
mod auth;
mod config;
mod crypto;
mod setup;
mod vcp;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use api::TeslaClient;
use config::Config;
use vcp::{commands::Command, VcpClient};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "tescmd", about = "Tesla Fleet API CLI")]
struct Cli {
    /// Vehicle VIN (overrides TESLA_VIN env var and config)
    #[arg(long, env = "TESLA_VIN", global = true)]
    vin: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive first-run wizard
    Setup,

    /// Vehicle queries and commands
    Vehicle {
        #[command(subcommand)]
        cmd: VehicleCmd,
    },

    /// Climate commands
    Climate {
        #[command(subcommand)]
        cmd: ClimateCmd,
    },

    /// Charging commands
    Charge {
        #[command(subcommand)]
        cmd: ChargeCmd,
    },
}

#[derive(Subcommand)]
enum VehicleCmd {
    /// List all vehicles on the account
    List,
    /// Fetch full vehicle_data snapshot
    Data,
    /// Wake the vehicle (unsigned REST)
    Wake,
    /// Lock doors (VCP VCSEC)
    Lock,
    /// Unlock doors (VCP VCSEC)
    Unlock,
    /// Flash lights (VCP Infotainment)
    Flash,
    /// Honk horn (VCP Infotainment)
    Honk,
}

#[derive(Subcommand)]
enum ClimateCmd {
    /// Turn climate on
    Start,
    /// Turn climate off
    Stop,
    /// Set cabin temperature (°C)
    SetTemp {
        #[arg(short = 't', long)]
        temp: f32,
    },
}

#[derive(Subcommand)]
enum ChargeCmd {
    /// Start charging
    Start,
    /// Stop charging
    Stop,
    /// Set charge limit (0–100)
    SetLimit {
        #[arg(short = 'l', long)]
        limit: u32,
    },
    /// Set charging amps
    SetAmps {
        #[arg(short = 'a', long)]
        amps: u32,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => setup::run().await,

        Commands::Vehicle { cmd } => {
            let config = Config::load()?;
            let client = TeslaClient::new(config.clone());
            match cmd {
                VehicleCmd::List => cmd_vehicle_list(&client).await,
                VehicleCmd::Data => cmd_vehicle_data(&client, cli.vin.as_deref()).await,
                VehicleCmd::Wake => cmd_vehicle_wake(&client, cli.vin.as_deref()).await,
                VehicleCmd::Lock => cmd_vcp(&client, &config, cli.vin.as_deref(), Command::Lock).await,
                VehicleCmd::Unlock => cmd_vcp(&client, &config, cli.vin.as_deref(), Command::Unlock).await,
                VehicleCmd::Flash => cmd_vcp(&client, &config, cli.vin.as_deref(), Command::Flash).await,
                VehicleCmd::Honk => cmd_vcp(&client, &config, cli.vin.as_deref(), Command::Honk).await,
            }
        }

        Commands::Climate { cmd } => {
            let config = Config::load()?;
            let client = TeslaClient::new(config.clone());
            let command = match cmd {
                ClimateCmd::Start => Command::ClimateStart,
                ClimateCmd::Stop => Command::ClimateStop,
                ClimateCmd::SetTemp { temp } => Command::ClimateSetTemp { temp_c: temp },
            };
            cmd_vcp(&client, &config, cli.vin.as_deref(), command).await
        }

        Commands::Charge { cmd } => {
            let config = Config::load()?;
            let client = TeslaClient::new(config.clone());
            let command = match cmd {
                ChargeCmd::Start => Command::ChargeStart,
                ChargeCmd::Stop => Command::ChargeStop,
                ChargeCmd::SetLimit { limit } => Command::ChargeSetLimit { percent: limit },
                ChargeCmd::SetAmps { amps } => Command::ChargeSetAmps { amps },
            };
            cmd_vcp(&client, &config, cli.vin.as_deref(), command).await
        }
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

async fn cmd_vehicle_list(client: &TeslaClient) -> Result<()> {
    let vehicles = client.list_vehicles().await?;
    if vehicles.is_empty() {
        println!("No vehicles found.");
        return Ok(());
    }
    for v in &vehicles {
        let vin = v["vin"].as_str().unwrap_or("unknown");
        let name = v["display_name"].as_str().unwrap_or("unnamed");
        let state = v["state"].as_str().unwrap_or("?");
        println!("{:20}  {:25}  {}", vin, name, state);
    }
    Ok(())
}

async fn cmd_vehicle_data(client: &TeslaClient, vin_arg: Option<&str>) -> Result<()> {
    let vin = client.resolve_vin(vin_arg).await?;
    let data = client.vehicle_data(&vin).await?;
    println!("{}", serde_json::to_string_pretty(&data)?);
    Ok(())
}

async fn cmd_vehicle_wake(client: &TeslaClient, vin_arg: Option<&str>) -> Result<()> {
    let vin = client.resolve_vin(vin_arg).await?;
    println!("Waking {}...", vin);
    let resp = client.wake_vehicle(&vin).await?;
    let state = resp["state"].as_str().unwrap_or("unknown");
    println!("State: {}", state);
    Ok(())
}

async fn cmd_vcp(
    client: &TeslaClient,
    config: &Config,
    vin_arg: Option<&str>,
    command: Command,
) -> Result<()> {
    let vin = client.resolve_vin(vin_arg).await?;

    // Load private key
    let key_path = Config::private_key_path();
    let private_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("Loading private key from {} — run 'tescmd setup'", key_path.display()))?;

    let mut vcp = VcpClient::new(&private_pem)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let token = config.access_token().await?;

    println!("Sending {:?} to {}...", command, vin);
    vcp.send_command(&http, config.base_url(), &token, &vin, &command)
        .await?;
    println!("OK");
    Ok(())
}
