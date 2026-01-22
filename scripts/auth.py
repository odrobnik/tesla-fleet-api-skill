#!/usr/bin/env python3
"""Tesla Fleet API authentication and configuration.

Usage:
    auth.py login                    # OAuth flow
    auth.py refresh                  # Refresh tokens
    auth.py register --domain X      # Register app domain
    auth.py config                   # Show config
    auth.py config set --base-url X  # Set config value
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
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.clawdbot/tesla-fleet-api/tesla-fleet.json")


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TeslaConfig:
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None
    audience: str = DEFAULT_AUDIENCE_EU
    base_url: Optional[str] = None
    ca_cert: Optional[str] = None
    domain: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


def load_config(path: str) -> TeslaConfig:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raw = {}

    return TeslaConfig(
        client_id=os.environ.get("TESLA_CLIENT_ID") or raw.get("client_id"),
        client_secret=os.environ.get("TESLA_CLIENT_SECRET") or raw.get("client_secret"),
        redirect_uri=os.environ.get("TESLA_REDIRECT_URI") or raw.get("redirect_uri"),
        audience=os.environ.get("TESLA_AUDIENCE") or raw.get("audience") or DEFAULT_AUDIENCE_EU,
        base_url=os.environ.get("TESLA_BASE_URL") or raw.get("base_url"),
        ca_cert=os.environ.get("TESLA_CA_CERT") or raw.get("ca_cert"),
        domain=os.environ.get("TESLA_DOMAIN") or raw.get("domain"),
        access_token=os.environ.get("TESLA_ACCESS_TOKEN") or raw.get("access_token"),
        refresh_token=os.environ.get("TESLA_REFRESH_TOKEN") or raw.get("refresh_token"),
    )


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
    raw = {k: v for k, v in raw.items() if v is not None}
    
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(raw, f, indent=2, sort_keys=True)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, path)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────

def form_post(url: str, fields: Dict[str, str]) -> Any:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url=url, method="POST", data=body, headers=headers)
    ctx = ssl.create_default_context()
    
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = text
        raise RuntimeError(f"HTTP {e.code}: {payload}")


def http_json(
    method: str,
    url: str,
    token: str,
    json_body: Optional[Dict[str, Any]] = None,
    ca_cert: Optional[str] = None,
) -> Any:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url=url, method=method, data=body, headers=headers)
    ctx = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {text}")


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_login(args, cfg: TeslaConfig, config_path: str) -> int:
    """Generate OAuth URL and optionally exchange code."""
    if not cfg.client_id or not cfg.redirect_uri:
        print("Missing client_id or redirect_uri in config.", file=sys.stderr)
        print(f"Set them with: auth.py config set --client-id X --redirect-uri Y", file=sys.stderr)
        return 1
    
    scope = "openid offline_access vehicle_device_data vehicle_cmds vehicle_location"
    state = secrets.token_hex(16)
    
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": scope,
        "state": state,
        "locale": "en-US",
        "prompt": "login",
    }
    
    url = TESLA_AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)
    
    print("Open this URL to authorize:")
    print()
    print(url)
    print()
    print(f"State: {state}")
    print()
    
    code = input("Paste the 'code' from the callback URL: ").strip()
    
    if not code:
        print("No code provided.", file=sys.stderr)
        return 1
    
    return cmd_exchange(args, cfg, config_path, code)


def cmd_exchange(args, cfg: TeslaConfig, config_path: str, code: Optional[str] = None) -> int:
    """Exchange authorization code for tokens."""
    code = code or args.code
    
    if not cfg.client_id or not cfg.client_secret or not cfg.redirect_uri:
        print("Missing client_id, client_secret, or redirect_uri.", file=sys.stderr)
        return 1
    
    fields = {
        "grant_type": "authorization_code",
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "code": code,
        "audience": cfg.audience,
        "redirect_uri": cfg.redirect_uri,
    }
    
    try:
        payload = form_post(FLEET_AUTH_TOKEN_URL, fields)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    cfg.access_token = payload.get("access_token")
    cfg.refresh_token = payload.get("refresh_token")
    save_config(config_path, cfg)
    
    print("✅ Tokens saved")
    print(f"   Access token:  ...{cfg.access_token[-20:]}")
    print(f"   Refresh token: ...{cfg.refresh_token[-20:]}")
    return 0


def cmd_refresh(args, cfg: TeslaConfig, config_path: str) -> int:
    """Refresh access token."""
    if not cfg.client_id or not cfg.refresh_token:
        print("Missing client_id or refresh_token.", file=sys.stderr)
        return 1
    
    fields = {
        "grant_type": "refresh_token",
        "client_id": cfg.client_id,
        "refresh_token": cfg.refresh_token,
    }
    
    try:
        payload = form_post(FLEET_AUTH_TOKEN_URL, fields)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    cfg.access_token = payload.get("access_token")
    if payload.get("refresh_token"):
        cfg.refresh_token = payload.get("refresh_token")
    save_config(config_path, cfg)
    
    print("✅ Token refreshed")
    print(f"   Access token: ...{cfg.access_token[-20:]}")
    return 0


def cmd_register(args, cfg: TeslaConfig, config_path: str) -> int:
    """Register app domain for Fleet API."""
    domain = args.domain or cfg.domain
    if not domain:
        print("Specify --domain", file=sys.stderr)
        return 1
    
    if not cfg.client_id or not cfg.client_secret:
        print("Missing client_id or client_secret.", file=sys.stderr)
        return 1
    
    # Get partner token
    fields = {
        "grant_type": "client_credentials",
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "audience": cfg.audience,
    }
    
    try:
        token_resp = form_post(FLEET_AUTH_TOKEN_URL, fields)
        partner_token = token_resp.get("access_token")
    except RuntimeError as e:
        print(f"Error getting partner token: {e}", file=sys.stderr)
        return 1
    
    # Register domain
    base = (cfg.base_url or cfg.audience).rstrip("/")
    url = f"{base}/api/1/partner_accounts"
    
    try:
        result = http_json("POST", url, partner_token, {"domain": domain}, cfg.ca_cert)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    cfg.domain = domain
    save_config(config_path, cfg)
    
    print(f"✅ Domain registered: {domain}")
    print()
    print("Next step: Enroll your key on the vehicle:")
    print(f"  https://tesla.com/_ak/{domain}")
    return 0


def cmd_config_show(args, cfg: TeslaConfig) -> int:
    """Show current config (redacted)."""
    print(f"📁 Config: {args.config}")
    print()
    print(f"🔑 Client ID:     {cfg.client_id or '(not set)'}")
    print(f"🔒 Client Secret: {'***' if cfg.client_secret else '(not set)'}")
    print(f"🔗 Redirect URI:  {cfg.redirect_uri or '(not set)'}")
    print(f"🌍 Audience:      {cfg.audience}")
    print(f"🖥️  Base URL:      {cfg.base_url or '(using audience)'}")
    print(f"📜 CA Cert:       {cfg.ca_cert or '(not set)'}")
    print(f"🏠 Domain:        {cfg.domain or '(not set)'}")
    print()
    print(f"🎫 Access Token:  {'***' if cfg.access_token else '(not set)'}")
    print(f"🔄 Refresh Token: {'***' if cfg.refresh_token else '(not set)'}")
    return 0


def cmd_config_set(args, cfg: TeslaConfig, config_path: str) -> int:
    """Set config values."""
    changed = []
    
    if args.client_id is not None:
        cfg.client_id = args.client_id
        changed.append("client_id")
    if args.client_secret is not None:
        cfg.client_secret = args.client_secret
        changed.append("client_secret")
    if args.redirect_uri is not None:
        cfg.redirect_uri = args.redirect_uri
        changed.append("redirect_uri")
    if args.audience is not None:
        cfg.audience = args.audience
        changed.append("audience")
    if args.base_url is not None:
        cfg.base_url = args.base_url
        changed.append("base_url")
    if args.ca_cert is not None:
        cfg.ca_cert = args.ca_cert
        changed.append("ca_cert")
    if args.domain is not None:
        cfg.domain = args.domain
        changed.append("domain")
    
    if not changed:
        print("No changes specified.", file=sys.stderr)
        return 1
    
    save_config(config_path, cfg)
    print(f"✅ Updated: {', '.join(changed)}")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auth.py",
        description="Tesla Fleet API authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  auth.py login                      # OAuth login flow
  auth.py refresh                    # Refresh tokens
  auth.py register --domain X        # Register app domain
  auth.py config                     # Show config
  auth.py config set --base-url X    # Set config value
"""
    )
    
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Config file path")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # login
    subparsers.add_parser("login", help="OAuth login flow (interactive)")
    
    # exchange (hidden, for direct code exchange)
    p_exchange = subparsers.add_parser("exchange", help="Exchange auth code for tokens")
    p_exchange.add_argument("code", help="Authorization code")
    
    # refresh
    subparsers.add_parser("refresh", help="Refresh access token")
    
    # register
    p_register = subparsers.add_parser("register", help="Register app domain")
    p_register.add_argument("--domain", help="App domain (e.g., drobnik.com)")
    
    # config
    p_config = subparsers.add_parser("config", help="Show or set config")
    config_sub = p_config.add_subparsers(dest="config_action")
    
    p_config_set = config_sub.add_parser("set", help="Set config values")
    p_config_set.add_argument("--client-id", dest="client_id")
    p_config_set.add_argument("--client-secret", dest="client_secret")
    p_config_set.add_argument("--redirect-uri", dest="redirect_uri")
    p_config_set.add_argument("--audience")
    p_config_set.add_argument("--base-url", dest="base_url")
    p_config_set.add_argument("--ca-cert", dest="ca_cert")
    p_config_set.add_argument("--domain")
    
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    
    cfg = load_config(args.config)
    
    if args.command == "login":
        return cmd_login(args, cfg, args.config)
    elif args.command == "exchange":
        return cmd_exchange(args, cfg, args.config)
    elif args.command == "refresh":
        return cmd_refresh(args, cfg, args.config)
    elif args.command == "register":
        return cmd_register(args, cfg, args.config)
    elif args.command == "config":
        if args.config_action == "set":
            return cmd_config_set(args, cfg, args.config)
        else:
            return cmd_config_show(args, cfg)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
