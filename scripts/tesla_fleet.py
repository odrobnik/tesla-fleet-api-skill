#!/usr/bin/env python3
"""Tesla Fleet API helper (unofficial wrapper script).

Goals:
- Keep dependencies to stdlib only.
- Support personal/hobbyist workflows: OAuth authorize URL, code exchange, refresh.
- Support occasional reads (vehicle list, vehicle_data) and basic commands (HVAC start/stop).

Notes:
- Tesla Fleet API is regional. For Europe use https://fleet-api.prd.eu.vn.cloud.tesla.com
- OAuth token endpoint for exchanges: https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token
- OAuth authorize endpoint: https://auth.tesla.com/oauth2/v3/authorize

This script does NOT run a callback server; you paste the returned `code`.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

FLEET_AUTH_TOKEN_URL = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
TESLA_AUTHORIZE_URL = "https://auth.tesla.com/oauth2/v3/authorize"

DEFAULT_AUDIENCE_EU = "https://fleet-api.prd.eu.vn.cloud.tesla.com"
DEFAULT_AUDIENCE_NA = "https://fleet-api.prd.na.vn.cloud.tesla.com"
DEFAULT_AUDIENCE_CN = "https://fleet-api.prd.cn.vn.cloud.tesla.cn"

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.clawdbot/tesla-fleet-api/tesla-fleet.json")


def _mkdirp(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _read_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _write_json_private(path: str, obj: Dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    if parent:
        _mkdirp(parent)
    data = json.dumps(obj, indent=2, sort_keys=True)
    # Write with restrictive permissions.
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, path)


def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    return v if v not in (None, "") else None


@dataclass
class TeslaConfig:
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    audience: str = DEFAULT_AUDIENCE_EU
    base_url: Optional[str] = None  # If set, overrides API base URL (e.g. https://localhost:4443)
    ca_cert: Optional[str] = None
    domain: Optional[str] = None  # App domain used for partner_accounts registration

    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


def load_config(path: str) -> TeslaConfig:
    raw = _read_json(path)

    cfg = TeslaConfig(
        client_id=_env("TESLA_CLIENT_ID") or raw.get("client_id"),
        client_secret=_env("TESLA_CLIENT_SECRET") or raw.get("client_secret"),
        redirect_uri=_env("TESLA_REDIRECT_URI") or raw.get("redirect_uri"),
        audience=_env("TESLA_AUDIENCE") or raw.get("audience") or DEFAULT_AUDIENCE_EU,
        base_url=_env("TESLA_BASE_URL") or raw.get("base_url"),
        ca_cert=_env("TESLA_CA_CERT") or raw.get("ca_cert"),
        domain=_env("TESLA_DOMAIN") or raw.get("domain"),
        access_token=_env("TESLA_ACCESS_TOKEN") or raw.get("access_token"),
        refresh_token=_env("TESLA_REFRESH_TOKEN") or raw.get("refresh_token"),
    )

    # Default base_url to audience if not explicitly set.
    if not cfg.base_url:
        cfg.base_url = cfg.audience

    return cfg


def save_config(path: str, cfg: TeslaConfig) -> None:
    raw = {
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "redirect_uri": cfg.redirect_uri,
        "audience": cfg.audience,
        "base_url": cfg.base_url,
        "ca_cert": cfg.ca_cert,
        "domain": cfg.domain,
        "access_token": cfg.access_token,
        "refresh_token": cfg.refresh_token,
    }
    # Remove None values.
    raw = {k: v for k, v in raw.items() if v is not None}
    _write_json_private(path, raw)


def http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    ca_cert: Optional[str] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    headers = headers or {}
    req = urllib.request.Request(url=url, method=method.upper(), data=body, headers=headers)

    ctx = None
    if url.startswith("https://"):
        if ca_cert:
            ctx = ssl.create_default_context(cafile=ca_cert)
        else:
            ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            data = resp.read()
            resp_headers = {k.lower(): v for (k, v) in resp.headers.items()}
            return resp.status, resp_headers, data
    except urllib.error.HTTPError as e:
        data = e.read() if hasattr(e, "read") else b""
        resp_headers = {k.lower(): v for (k, v) in (e.headers.items() if e.headers else [])}
        return e.code, resp_headers, data


def http_json(
    method: str,
    url: str,
    token: Optional[str] = None,
    json_body: Optional[Dict[str, Any]] = None,
    ca_cert: Optional[str] = None,
) -> Any:
    headers: Dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    status, _, data = http_request(method, url, headers=headers, body=body, ca_cert=ca_cert)

    # Provide helpful errors.
    text = data.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = text

    if not (200 <= status <= 299):
        raise RuntimeError(f"HTTP {status} from {url}: {payload}")

    return payload


def form_post(url: str, fields: Dict[str, str], ca_cert: Optional[str] = None) -> Any:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    status, _, data = http_request("POST", url, headers=headers, body=body, ca_cert=ca_cert)
    text = data.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = text
    if not (200 <= status <= 299):
        raise RuntimeError(f"HTTP {status} from {url}: {payload}")
    return payload


def cmd_auth_url(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    client_id = args.client_id or cfg.client_id
    redirect_uri = args.redirect_uri or cfg.redirect_uri
    if not client_id or not redirect_uri:
        print("Missing client_id/redirect_uri. Set in config or env (TESLA_CLIENT_ID, TESLA_REDIRECT_URI).", file=sys.stderr)
        return 2

    scope = args.scope
    state = args.state or secrets.token_hex(16)
    nonce = args.nonce

    q = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }
    if nonce:
        q["nonce"] = nonce
    if args.locale:
        q["locale"] = args.locale
    if args.prompt:
        q["prompt"] = args.prompt
    if args.prompt_missing_scopes is not None:
        q["prompt_missing_scopes"] = "true" if args.prompt_missing_scopes else "false"
    if args.require_requested_scopes is not None:
        q["require_requested_scopes"] = "true" if args.require_requested_scopes else "false"
    if args.show_keypair_step is not None:
        q["show_keypair_step"] = "true" if args.show_keypair_step else "false"

    url = TESLA_AUTHORIZE_URL + "?" + urllib.parse.urlencode(q)
    print(url)
    if args.print_state:
        print(f"\nstate={state}")
    return 0


def cmd_exchange_code(args: argparse.Namespace, cfg: TeslaConfig, config_path: str) -> int:
    client_id = args.client_id or cfg.client_id
    client_secret = args.client_secret or cfg.client_secret
    redirect_uri = args.redirect_uri or cfg.redirect_uri
    audience = args.audience or cfg.audience

    if not client_id or not client_secret or not redirect_uri:
        print("Missing client_id/client_secret/redirect_uri.", file=sys.stderr)
        return 2

    fields = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": args.code,
        "audience": audience,
        "redirect_uri": redirect_uri,
    }
    if args.scope:
        fields["scope"] = args.scope

    payload = form_post(FLEET_AUTH_TOKEN_URL, fields, ca_cert=None)
    cfg.access_token = payload.get("access_token")
    cfg.refresh_token = payload.get("refresh_token")
    save_config(config_path, cfg)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_refresh(args: argparse.Namespace, cfg: TeslaConfig, config_path: str) -> int:
    client_id = args.client_id or cfg.client_id
    refresh_token = args.refresh_token or cfg.refresh_token
    if not client_id or not refresh_token:
        print("Missing client_id/refresh_token.", file=sys.stderr)
        return 2

    fields = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }

    payload = form_post(FLEET_AUTH_TOKEN_URL, fields, ca_cert=None)
    # Refresh-token rotation: always save the new refresh token.
    cfg.access_token = payload.get("access_token")
    if payload.get("refresh_token"):
        cfg.refresh_token = payload.get("refresh_token")
    save_config(config_path, cfg)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_partner_token(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    client_id = args.client_id or cfg.client_id
    client_secret = args.client_secret or cfg.client_secret
    audience = args.audience or cfg.audience

    if not client_id or not client_secret:
        print("Missing client_id/client_secret.", file=sys.stderr)
        return 2

    fields = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": audience,
    }
    if args.scope:
        fields["scope"] = args.scope

    payload = form_post(FLEET_AUTH_TOKEN_URL, fields, ca_cert=None)
    print(json.dumps(payload, indent=2))
    return 0


def get_partner_access_token(cfg: TeslaConfig, *, audience: Optional[str] = None, scope: Optional[str] = None) -> str:
    if not cfg.client_id or not cfg.client_secret:
        raise RuntimeError("Missing client_id/client_secret (required for partner token).")

    fields = {
        "grant_type": "client_credentials",
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "audience": audience or cfg.audience,
    }
    if scope:
        fields["scope"] = scope

    payload = form_post(FLEET_AUTH_TOKEN_URL, fields, ca_cert=None)
    token = payload.get("access_token")
    if not token:
        raise RuntimeError(f"Partner token response missing access_token: {payload}")
    return token


def cmd_register(args: argparse.Namespace, cfg: TeslaConfig, config_path: str) -> int:
    # Register app domain in the current region (required before any API access).
    domain = (args.domain or cfg.domain or "").strip().lower()
    if not domain:
        print("Missing domain. Provide --domain drobnik.com or set TESLA_DOMAIN / config.domain.", file=sys.stderr)
        return 2

    audience = args.audience or cfg.audience

    partner_token = get_partner_access_token(cfg, audience=audience, scope=args.scope)

    payload = http_json(
        "POST",
        _api_url(cfg, "/api/1/partner_accounts"),
        token=partner_token,
        json_body={"domain": domain},
        ca_cert=cfg.ca_cert,
    )

    # Persist domain for convenience.
    cfg.domain = domain
    save_config(config_path, cfg)

    print(json.dumps(payload, indent=2))
    return 0


def _api_url(cfg: TeslaConfig, path: str) -> str:
    base = (cfg.base_url or cfg.audience).rstrip("/")
    return base + path


def format_vehicles_human(vehicles: list) -> str:
    """Format vehicle list for human-readable output."""
    if not vehicles:
        return "No vehicles found."
    
    lines = []
    for i, v in enumerate(vehicles):
        name = v.get("display_name", "Unknown")
        vin = v.get("vin", "?")
        state = v.get("state", "unknown")
        access = v.get("access_type", "?")
        
        # State indicator
        state_icon = "🟢" if state == "online" else "🔴" if state == "offline" else "💤" if state == "asleep" else "⚪"
        
        if i > 0:
            lines.append("")
        lines.append(f"🚗 Name:   {name}")
        lines.append(f"🔖 VIN:    {vin}")
        lines.append(f"{state_icon} Status: {state.capitalize()}")
        lines.append(f"👤 Access: {access.capitalize()}")
    
    return "\n".join(lines)


def cmd_list_vehicles(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token. Use exchange-code or set TESLA_ACCESS_TOKEN.", file=sys.stderr)
        return 2

    payload = http_json("GET", _api_url(cfg, "/api/1/vehicles"), token=token, ca_cert=cfg.ca_cert)
    
    if getattr(args, "raw_json", False):
        print(json.dumps(payload, indent=2))
    else:
        vehicles = payload.get("response", [])
        print(format_vehicles_human(vehicles))
    return 0


def cmd_vehicle_data(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json("GET", _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/vehicle_data"), token=token, ca_cert=cfg.ca_cert)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_wake_up(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json("POST", _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/wake_up"), token=token, json_body={}, ca_cert=cfg.ca_cert)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_climate_start(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/auto_conditioning_start"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_climate_stop(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/auto_conditioning_stop"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_honk_horn(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/honk_horn"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_flash_lights(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/flash_lights"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_door_lock(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/door_lock"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_door_unlock(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/door_unlock"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_charge_start(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/charge_start"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_charge_stop(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/charge_stop"),
        token=token,
        json_body={},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_charge_state(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    # Fetch vehicle_data with charge_state endpoint
    payload = http_json(
        "GET",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/vehicle_data?endpoints=charge_state"),
        token=token,
        ca_cert=cfg.ca_cert,
    )
    # Extract just the charge_state for cleaner output
    if payload and "response" in payload and "charge_state" in payload["response"]:
        charge_state = payload["response"]["charge_state"]
        print(json.dumps(charge_state, indent=2))
    else:
        print(json.dumps(payload, indent=2))
    return 0


def cmd_set_charge_limit(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    percent = args.percent
    if percent < 50 or percent > 100:
        print("Charge limit must be between 50 and 100 percent.", file=sys.stderr)
        return 2

    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/set_charge_limit"),
        token=token,
        json_body={"percent": percent},
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_set_temps(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    body = {
        "driver_temp": args.driver_temp,
        "passenger_temp": args.passenger_temp,
    }
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/set_temps"),
        token=token,
        json_body=body,
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_set_scheduled_departure(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    body = {
        "enable": args.enable,
        "departure_time": args.departure_time,
        "preconditioning_enabled": args.preconditioning_enabled,
        "preconditioning_weekdays_only": args.preconditioning_weekdays_only,
    }
    if args.off_peak_charging_enabled is not None:
        body["off_peak_charging_enabled"] = args.off_peak_charging_enabled
    if args.off_peak_charging_weekdays_only is not None:
        body["off_peak_charging_weekdays_only"] = args.off_peak_charging_weekdays_only
    if args.end_off_peak_time is not None:
        body["end_off_peak_time"] = args.end_off_peak_time

    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/set_scheduled_departure"),
        token=token,
        json_body=body,
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_set_climate_keeper_mode(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    body = {"climate_keeper_mode": args.mode}
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/set_climate_keeper_mode"),
        token=token,
        json_body=body,
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_remote_seat_heater_request(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    body = {
        "heater": args.heater,
        "level": args.level,
    }
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/remote_seat_heater_request"),
        token=token,
        json_body=body,
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_remote_steering_wheel_heater_request(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    token = args.access_token or cfg.access_token
    if not token:
        print("Missing access token.", file=sys.stderr)
        return 2

    vehicle_tag = args.vehicle_tag
    body = {"on": args.on}
    payload = http_json(
        "POST",
        _api_url(cfg, f"/api/1/vehicles/{urllib.parse.quote(vehicle_tag)}/command/remote_steering_wheel_heater_request"),
        token=token,
        json_body=body,
        ca_cert=cfg.ca_cert,
    )
    print(json.dumps(payload, indent=2))
    return 0


def cmd_config_show(args: argparse.Namespace, cfg: TeslaConfig) -> int:
    # Redact secrets.
    out = {
        "client_id": cfg.client_id,
        "client_secret": "***" if cfg.client_secret else None,
        "redirect_uri": cfg.redirect_uri,
        "audience": cfg.audience,
        "base_url": cfg.base_url,
        "ca_cert": cfg.ca_cert,
        "domain": cfg.domain,
        "access_token": "***" if cfg.access_token else None,
        "refresh_token": "***" if cfg.refresh_token else None,
    }
    out = {k: v for k, v in out.items() if v is not None}
    print(json.dumps(out, indent=2))
    return 0


def cmd_config_set(args: argparse.Namespace, cfg: TeslaConfig, config_path: str) -> int:
    if args.client_id is not None:
        cfg.client_id = args.client_id
    if args.client_secret is not None:
        cfg.client_secret = args.client_secret
    if args.redirect_uri is not None:
        cfg.redirect_uri = args.redirect_uri
    if args.audience is not None:
        cfg.audience = args.audience
        if not args.base_url:
            cfg.base_url = cfg.audience
    if args.base_url is not None:
        cfg.base_url = args.base_url
    if args.ca_cert is not None:
        cfg.ca_cert = args.ca_cert
    if getattr(args, "domain", None) is not None:
        cfg.domain = args.domain

    save_config(config_path, cfg)
    print(f"Saved {config_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tesla_fleet.py", description="Tesla Fleet API helper")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help=f"Config path (default: {DEFAULT_CONFIG_PATH})")

    sp = p.add_subparsers(dest="cmd", required=True)

    p_auth = sp.add_parser("auth-url", help="Print the Tesla OAuth authorize URL")
    p_auth.add_argument("--client-id")
    p_auth.add_argument("--redirect-uri")
    p_auth.add_argument(
        "--scope",
        default="openid offline_access vehicle_device_data vehicle_cmds",
        help="Space-delimited scopes",
    )
    p_auth.add_argument("--state")
    p_auth.add_argument("--nonce")
    p_auth.add_argument("--locale", default="en-US")
    p_auth.add_argument("--prompt", default="login")
    p_auth.add_argument("--prompt-missing-scopes", dest="prompt_missing_scopes", action=argparse.BooleanOptionalAction, default=None)
    p_auth.add_argument("--require-requested-scopes", dest="require_requested_scopes", action=argparse.BooleanOptionalAction, default=None)
    p_auth.add_argument("--show-keypair-step", dest="show_keypair_step", action=argparse.BooleanOptionalAction, default=None)
    p_auth.add_argument("--print-state", action="store_true", help="Also print the state value")

    p_code = sp.add_parser("exchange-code", help="Exchange authorization code for access/refresh tokens")
    p_code.add_argument("code")
    p_code.add_argument("--client-id")
    p_code.add_argument("--client-secret")
    p_code.add_argument("--redirect-uri")
    p_code.add_argument("--audience", help="Fleet API base URL (region). Example: https://fleet-api.prd.eu.vn.cloud.tesla.com")
    p_code.add_argument("--scope", help="Optional scopes")

    p_ref = sp.add_parser("refresh", help="Refresh access token (rotates refresh_token)")
    p_ref.add_argument("--client-id")
    p_ref.add_argument("--refresh-token")

    p_pt = sp.add_parser("partner-token", help="Get a partner token (client_credentials)")
    p_pt.add_argument("--client-id")
    p_pt.add_argument("--client-secret")
    p_pt.add_argument("--audience", help="Fleet API base URL (region).")
    p_pt.add_argument("--scope", default="openid vehicle_device_data vehicle_cmds vehicle_charging_cmds")

    p_reg = sp.add_parser("register", help="Register the app domain in the current region (POST /api/1/partner_accounts)")
    p_reg.add_argument("--domain", help="App domain, e.g. drobnik.com")
    p_reg.add_argument("--audience", help="Fleet API base URL (region).")
    p_reg.add_argument("--scope", default=None, help="Optional partner-token scopes")

    p_vehicles = sp.add_parser("vehicles", help="List vehicles (GET /api/1/vehicles)")
    p_vehicles.add_argument("--json", action="store_true", dest="raw_json", help="Output raw JSON")

    p_vd = sp.add_parser("vehicle-data", help="Fetch live vehicle_data (GET /vehicle_data)")
    p_vd.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_wu = sp.add_parser("wake-up", help="Wake vehicle")
    p_wu.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_cs = sp.add_parser("climate-start", help="Start HVAC preconditioning")
    p_cs.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_cx = sp.add_parser("climate-stop", help="Stop HVAC preconditioning")
    p_cx.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_honk = sp.add_parser("honk-horn", help="Honk the horn")
    p_honk.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_flash = sp.add_parser("flash-lights", help="Flash the lights")
    p_flash.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_lock = sp.add_parser("door-lock", help="Lock the doors")
    p_lock.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_unlock = sp.add_parser("door-unlock", help="Unlock the doors")
    p_unlock.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_charge_start = sp.add_parser("charge-start", help="Start charging")
    p_charge_start.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_charge_stop = sp.add_parser("charge-stop", help="Stop charging")
    p_charge_stop.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_charge_state = sp.add_parser("charge-state", help="Get charging state (battery level, limit, status)")
    p_charge_state.add_argument("vehicle_tag", help="VIN or vehicle_tag")

    p_set_charge_limit = sp.add_parser("set-charge-limit", help="Set charge limit percentage")
    p_set_charge_limit.add_argument("vehicle_tag", help="VIN or vehicle_tag")
    p_set_charge_limit.add_argument("percent", type=int, help="Charge limit (50-100)")

    p_set_temps = sp.add_parser("set-temps", help="Set target temperature")
    p_set_temps.add_argument("vehicle_tag", help="VIN or vehicle_tag")
    p_set_temps.add_argument("driver_temp", type=float, help="Driver temp in Celsius")
    p_set_temps.add_argument("passenger_temp", type=float, help="Passenger temp in Celsius")

    p_sched_dep = sp.add_parser("set-scheduled-departure", help="Set scheduled departure (HVAC preconditioning)")
    p_sched_dep.add_argument("vehicle_tag", help="VIN or vehicle_tag")
    p_sched_dep.add_argument("--enable", action="store_true", help="Enable scheduled departure")
    p_sched_dep.add_argument("--disable", dest="enable", action="store_false", help="Disable scheduled departure")
    p_sched_dep.add_argument("--departure-time", type=int, required=True, help="Departure time (minutes since midnight, e.g. 480 = 8:00 AM)")
    p_sched_dep.add_argument("--preconditioning-enabled", action="store_true", default=True, help="Enable preconditioning")
    p_sched_dep.add_argument("--preconditioning-weekdays-only", action="store_true", default=False, help="Precondition weekdays only")
    p_sched_dep.add_argument("--off-peak-charging-enabled", action="store_true", default=None, help="Enable off-peak charging")
    p_sched_dep.add_argument("--off-peak-charging-weekdays-only", action="store_true", default=None, help="Off-peak charging weekdays only")
    p_sched_dep.add_argument("--end-off-peak-time", type=int, default=None, help="End off-peak time (minutes since midnight)")
    p_sched_dep.set_defaults(enable=True)

    p_climate_keeper = sp.add_parser("set-climate-keeper-mode", help="Set climate keeper mode")
    p_climate_keeper.add_argument("vehicle_tag", help="VIN or vehicle_tag")
    p_climate_keeper.add_argument("mode", type=int, choices=[0, 1, 2, 3], help="Mode: 0=off, 1=keep, 2=dog, 3=camp")

    p_seat_heater = sp.add_parser("remote-seat-heater-request", help="Set seat heater level")
    p_seat_heater.add_argument("vehicle_tag", help="VIN or vehicle_tag")
    p_seat_heater.add_argument("heater", type=int, choices=[0, 1, 2, 4, 5], help="Seat: 0=driver, 1=passenger, 2=rear-left, 4=rear-center, 5=rear-right")
    p_seat_heater.add_argument("level", type=int, choices=[0, 1, 2, 3], help="Level: 0=off, 1=low, 2=medium, 3=high")

    p_steering_heater = sp.add_parser("remote-steering-wheel-heater-request", help="Set steering wheel heater")
    p_steering_heater.add_argument("vehicle_tag", help="VIN or vehicle_tag")
    p_steering_heater.add_argument("--on", action="store_true", dest="on", help="Turn on")
    p_steering_heater.add_argument("--off", action="store_false", dest="on", help="Turn off")
    p_steering_heater.set_defaults(on=True)

    p_cfg_show = sp.add_parser("config-show", help="Print current config (redacted)")

    p_cfg_set = sp.add_parser("config-set", help="Set config values")
    p_cfg_set.add_argument("--client-id")
    p_cfg_set.add_argument("--client-secret")
    p_cfg_set.add_argument("--redirect-uri")
    p_cfg_set.add_argument("--audience")
    p_cfg_set.add_argument("--base-url", help="Override API base URL (e.g. https://localhost:4443 when using tesla-http-proxy)")
    p_cfg_set.add_argument("--ca-cert", help="CA cert to trust for proxy TLS (e.g. ./config/tls-cert.pem)")
    p_cfg_set.add_argument("--domain", help="App domain used for partner_accounts registration (e.g. drobnik.com)")

    # Shared token override for API calls.
    for name in ["vehicles", "vehicle-data", "wake-up", "climate-start", "climate-stop", 
                 "honk-horn", "flash-lights", "door-lock", "door-unlock", "charge-start", "charge-stop",
                 "charge-state", "set-charge-limit", "set-temps", "set-scheduled-departure", "set-climate-keeper-mode", 
                 "remote-seat-heater-request", "remote-steering-wheel-heater-request"]:
        sub = sp.choices[name]
        sub.add_argument("--access-token", help="Override access token")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    cfg = load_config(args.config)

    if args.cmd == "auth-url":
        return cmd_auth_url(args, cfg)
    if args.cmd == "exchange-code":
        return cmd_exchange_code(args, cfg, args.config)
    if args.cmd == "refresh":
        return cmd_refresh(args, cfg, args.config)
    if args.cmd == "partner-token":
        return cmd_partner_token(args, cfg)
    if args.cmd == "register":
        return cmd_register(args, cfg, args.config)
    if args.cmd == "vehicles":
        return cmd_list_vehicles(args, cfg)
    if args.cmd == "vehicle-data":
        return cmd_vehicle_data(args, cfg)
    if args.cmd == "wake-up":
        return cmd_wake_up(args, cfg)
    if args.cmd == "climate-start":
        return cmd_climate_start(args, cfg)
    if args.cmd == "climate-stop":
        return cmd_climate_stop(args, cfg)
    if args.cmd == "honk-horn":
        return cmd_honk_horn(args, cfg)
    if args.cmd == "flash-lights":
        return cmd_flash_lights(args, cfg)
    if args.cmd == "door-lock":
        return cmd_door_lock(args, cfg)
    if args.cmd == "door-unlock":
        return cmd_door_unlock(args, cfg)
    if args.cmd == "charge-start":
        return cmd_charge_start(args, cfg)
    if args.cmd == "charge-stop":
        return cmd_charge_stop(args, cfg)
    if args.cmd == "charge-state":
        return cmd_charge_state(args, cfg)
    if args.cmd == "set-charge-limit":
        return cmd_set_charge_limit(args, cfg)
    if args.cmd == "set-temps":
        return cmd_set_temps(args, cfg)
    if args.cmd == "set-scheduled-departure":
        return cmd_set_scheduled_departure(args, cfg)
    if args.cmd == "set-climate-keeper-mode":
        return cmd_set_climate_keeper_mode(args, cfg)
    if args.cmd == "remote-seat-heater-request":
        return cmd_remote_seat_heater_request(args, cfg)
    if args.cmd == "remote-steering-wheel-heater-request":
        return cmd_remote_steering_wheel_heater_request(args, cfg)
    if args.cmd == "config-show":
        return cmd_config_show(args, cfg)
    if args.cmd == "config-set":
        return cmd_config_set(args, cfg, args.config)

    print(f"Unknown command: {args.cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
