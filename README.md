# Tesla Fleet API Skill

Control your Tesla via the official Fleet API.

## Quick Start

### Prerequisites
- Tesla Developer Account with an app created
- A domain you control (for public key hosting)
- macOS (scripts tested on macOS)

### 1. Setup (one-time, ~3 min)

```bash
# Install Go + build tesla-http-proxy
./scripts/setup_proxy.sh
```

### 2. Generate EC keypair and host it

```bash
# Generate P-256 keypair
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem

# Host public-key.pem on your domain at:
# https://YOUR_DOMAIN/.well-known/appspecific/com.tesla.3p.public-key.pem
```

### 3. OAuth + Register

```bash
# Get tokens (opens browser, captures OAuth callback)
python3 scripts/tesla_oauth_local.py \
  --client-id "YOUR_CLIENT_ID" \
  --client-secret "YOUR_CLIENT_SECRET" \
  --redirect-uri "http://localhost:18080/callback" \
  --audience "https://fleet-api.prd.eu.vn.cloud.tesla.com" \
  --scope "openid offline_access vehicle_device_data vehicle_cmds vehicle_location" \
  --prompt-missing-scopes

# Register domain in EU region
python3 scripts/tesla_fleet.py \
  --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json \
  register --domain YOUR_DOMAIN.com
```

### 4. Enroll Virtual Key

On your phone (Tesla app installed):
**https://tesla.com/_ak/YOUR_DOMAIN.com**

### 5. Start Proxy

```bash
./scripts/start_proxy.sh /path/to/private-key.pem
```

### 6. Configure to use proxy

```bash
python3 scripts/tesla_fleet.py \
  --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json \
  config-set \
  --base-url "https://localhost:4443" \
  --ca-cert "$HOME/.tesla-http-proxy/tls-cert.pem"
```

### 7. Use it!

```bash
# List vehicles
python3 scripts/tesla_fleet.py --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json vehicles

# Get vehicle data
python3 scripts/tesla_fleet.py --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json vehicle-data <VIN>

# Honk horn
python3 scripts/tesla_fleet.py --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json honk-horn <VIN>

# Start climate
python3 scripts/tesla_fleet.py --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json climate-start <VIN>

# Lock doors
python3 scripts/tesla_fleet.py --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json door-lock <VIN>
```

## Available Commands

### Data
- `vehicles` — List vehicles
- `vehicle-data <VIN>` — Get vehicle data
- `wake-up <VIN>` — Wake vehicle

### Climate
- `climate-start <VIN>` — Start HVAC
- `climate-stop <VIN>` — Stop HVAC
- `set-temps <VIN> <driver_temp> <passenger_temp>` — Set target temperature (°C)
- `set-scheduled-departure <VIN> --departure-time <minutes>` — Schedule preconditioning (minutes since midnight, e.g. 480 = 8:00 AM)
- `set-climate-keeper-mode <VIN> <mode>` — Climate keeper (0=off, 1=keep, 2=dog, 3=camp)
- `remote-seat-heater-request <VIN> <heater> <level>` — Seat heater (heater: 0=driver, 1=passenger, 2/4/5=rear; level: 0=off, 1=low, 2=med, 3=high)
- `remote-steering-wheel-heater-request <VIN> --on|--off` — Steering wheel heater

### Doors & Alerts
- `door-lock <VIN>` — Lock
- `door-unlock <VIN>` — Unlock
- `honk-horn <VIN>` — Honk
- `flash-lights <VIN>` — Flash lights

### Charging
- `charge-start <VIN>` — Start charging
- `charge-stop <VIN>` — Stop charging

## Troubleshooting

### "Missing scopes" error
Run OAuth flow again with `--prompt-missing-scopes`:
```bash
python3 scripts/tesla_oauth_local.py --prompt-missing-scopes ...
```

### "Tesla Vehicle Command Protocol required"
Means signing is required:
1. Make sure virtual key is enrolled: `https://tesla.com/_ak/YOUR_DOMAIN.com`
2. Start proxy: `./scripts/start_proxy.sh /path/to/private-key.pem`
3. Configure script to use proxy (step 6 above)

### "vehicle unavailable"
Vehicle is asleep. Wake it first:
```bash
python3 scripts/tesla_fleet.py --config ~/.clawdbot/tesla-fleet-api/tesla-fleet.json wake-up <VIN>
```

## Files

- `scripts/setup_proxy.sh` — One-time setup (install Go, build proxy)
- `scripts/start_proxy.sh` — Start proxy in background
- `scripts/stop_proxy.sh` — Stop proxy
- `scripts/tesla_oauth_local.py` — OAuth helper with local callback server
- `scripts/tesla_fleet.py` — Main CLI for all Tesla Fleet API operations

## Security Notes

- **Never commit secrets** (`client_secret`, `access_token`, `private-key.pem`)
- Tokens are stored in `~/.clawdbot/tesla-fleet-api/tesla-fleet.json` with mode `600`
- Private key should be stored securely (not in skill folder)
- The proxy runs locally only (`localhost:4443`)

## References

- Tesla Fleet API Docs: https://developer.tesla.com/docs/fleet-api
- Vehicle Command SDK: https://github.com/teslamotors/vehicle-command
