# tescmd-rs

A minimal, standalone Rust CLI for controlling Tesla vehicles via the [Tesla Fleet API](https://developer.tesla.com/docs/fleet-api).

**Key differentiator:** uses [AgentGen](https://www.agent-gen.com) for public-key hosting, eliminating the need for GitHub Pages, Tailscale, or any external infrastructure. Full Vehicle Command Protocol (VCP) with ECDH signing works on all modern Tesla vehicles.

---

## Requirements

- Rust 1.70+ (`rustup` recommended)
- A [Tesla Developer account](https://developer.tesla.com) with an OAuth app
- An [AgentGen](https://www.agent-gen.com) API key (free)

---

## Install

```bash
git clone <repo>
cd tescmd-rs
cargo build --release
# Binary is at: target/release/tescmd

# Optional: install to PATH
cargo install --path .
```

---

## First-time setup

Run the interactive wizard. It walks you through all 5 steps:

```bash
cargo run -- setup
# or after install:
tescmd setup
```

### What the wizard does

**Step 1 — AgentGen origin**
- Prompts for your AgentGen API key
- Provisions a subdomain (e.g. `abc123.agent-gen.com`) where your Tesla public key will be served
- No GitHub repo or Tailscale required

**Step 2 — Tesla Developer App**
- Prompts for your Tesla `client_id`, `client_secret`, and region (`na` / `eu` / `cn`)
- Register your app at https://developer.tesla.com
- Set the OAuth redirect URI to: `http://localhost:13227/callback`

**Step 3 — EC key pair**
- Generates a P-256 key pair and saves it to `~/.config/tescmd/keys/`
- Uploads the public key to AgentGen (served at the Tesla-expected `.well-known` path)
- Opens `https://tesla.com/_ak/<your-domain>` — **approve the key in your Tesla app**

**Step 4 — Partner registration**
- Registers your app with the Tesla Fleet API using a `client_credentials` token

**Step 5 — OAuth login**
- Opens a browser for Tesla login (PKCE flow)
- Saves tokens to `~/.config/tescmd/token.json`

### Files created by setup

```
~/.config/tescmd/
├── config.toml          # App credentials, region, AgentGen origin
├── token.json           # OAuth tokens (auto-refreshed)
└── keys/
    ├── private.pem      # PKCS#8 P-256 private key (mode 0600)
    └── public.pem       # SPKI P-256 public key (uploaded to AgentGen)
```

---

## Usage

### Global option

```bash
tescmd --vin <VIN> <command>
# or set once:
export TESLA_VIN=5YJ3E1EA...
```

If `--vin` / `TESLA_VIN` is omitted, the first vehicle on the account is used automatically.

---

### Vehicle commands

```bash
# List all vehicles
tescmd vehicle list

# Full vehicle data snapshot (JSON)
tescmd vehicle data

# Wake the vehicle (unsigned REST, no VCP needed)
tescmd vehicle wake

# Lock / unlock doors (VCP → VCSEC)
tescmd vehicle lock
tescmd vehicle unlock

# Flash lights / honk horn (VCP → Infotainment)
tescmd vehicle flash
tescmd vehicle honk
```

### Climate commands

```bash
# Turn climate on / off (VCP → Infotainment)
tescmd climate start
tescmd climate stop

# Set temperature in °C (sets both driver and passenger)
tescmd climate set-temp -t 22.5
```

### Charge commands

```bash
# Start / stop charging (VCP → Infotainment)
tescmd charge start
tescmd charge stop

# Set charge limit (0–100 %)
tescmd charge set-limit -l 80

# Set charging current (amps)
tescmd charge set-amps -a 16
```

---

## How VCP works

Commands that require the Vehicle Command Protocol (`lock`, `unlock`, `flash`, `honk`, all `climate` and `charge` subcommands) go through a signed ECDH channel:

1. **Handshake** — sends your 65-byte uncompressed P-256 public key to the vehicle; receives `SessionInfo` (counter, vehicle public key, epoch, clock time)
2. **Key derivation** — `session_key = SHA1(ECDH_shared_x)[:16]`, then `signing_key = HMAC-SHA256(session_key, "authenticated command")`
3. **Per-command signing** — builds a TLV metadata block and computes `HMAC-SHA256(signing_key, metadata || 0xFF || payload)`
4. **Session caching** — sessions are reused for 5 minutes; stale-session faults trigger an automatic re-handshake and retry

`vehicle wake` uses the unsigned REST path (`POST /wake_up`) and does not require a VCP session.

---

## Environment variables

| Variable | Description |
|---|---|
| `TESLA_VIN` | Default VIN (overridden by `--vin`) |

All other settings (client ID, region, tokens) are stored in `~/.config/tescmd/config.toml` and `token.json` by the setup wizard.

---

## Troubleshooting

**"Key not enrolled on vehicle"**
The virtual key approval step was skipped or not completed. Re-run `tescmd setup` and make sure to approve the key in the Tesla app when the enrollment URL opens.

**"Token expired … run 'tescmd setup'"**
The refresh token has expired (Tesla refresh tokens last ~45 days of inactivity). Re-run `tescmd setup` step 5 or just `tescmd setup` in full.

**"Handshake fault 3: UNKNOWN_KEY_ID"**
Same as the key-not-enrolled error above.

**"Handshake HTTP 408"**
The vehicle subsystem didn't respond in time — usually because the vehicle just woke up. Run `tescmd vehicle wake`, wait a few seconds, and retry.

**Command works on some vehicles but not others**
Older vehicles (pre-2021) may not support VCP. Check whether your vehicle supports Fleet API commands at https://developer.tesla.com/docs/fleet-api/vehicles/fleet-api-support.

---

## Project structure

```
src/
├── main.rs          # CLI (clap derive), command dispatch
├── config.rs        # TOML config + token JSON
├── auth.rs          # OAuth2 PKCE, token refresh, partner registration
├── api.rs           # TeslaClient (list/data/wake, VIN resolution)
├── crypto.rs        # P-256 keygen, ECDH + SHA-1 KDF
├── agentgen.rs      # AgentGen REST client (provision + upload)
├── setup.rs         # Interactive 5-step wizard
└── vcp/
    ├── mod.rs       # VcpClient: session cache, send_command()
    ├── proto.rs     # Hand-written protobuf primitives (no prost)
    ├── metadata.rs  # TLV metadata encoder
    └── commands.rs  # Payload builders for each command
```

No `.proto` files, no code generation — protobuf is hand-encoded to match Tesla's wire format exactly.
