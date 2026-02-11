#!/usr/bin/env bash
# Check for school events today and schedule Tesla preconditioning.
#
# Schedules:
# - 10 minutes before earliest school start
# - 10 minutes before EACH unique school end time (pickup)
#
# Requires:
# - icalBuddy
# - Tesla Fleet API config at ~/.openclaw/tesla-fleet-api/ (legacy: ~/.moltbot/tesla-fleet-api/)
# - tesla-http-proxy (used when config base_url is https://localhost:4443)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"      # skills/tesla-fleet-api
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"      # skills/tesla-fleet-api/scripts

PYTHON_BIN="${PYTHON_BIN:-/opt/homebrew/bin/python3}"
ICALBUDDY_BIN="${ICALBUDDY_BIN:-/opt/homebrew/bin/icalBuddy}"

NEW_DEFAULT="$HOME/.openclaw/tesla-fleet-api"
OLD_DEFAULT="$HOME/.moltbot/tesla-fleet-api"
DEFAULT_CONFIG_DIR="$NEW_DEFAULT"
if [ -d "$OLD_DEFAULT" ] && [ ! -d "$NEW_DEFAULT" ]; then
  DEFAULT_CONFIG_DIR="$OLD_DEFAULT"
fi
CONFIG_DIR="${TESLA_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
CONFIG_FILE="${CONFIG_DIR}/tesla-fleet.json"
LOG_FILE="${CONFIG_DIR}/school-precondition.log"

PROXY_DIR="${TESLA_PROXY_DIR:-${CONFIG_DIR}/proxy}"
PROXY_PID_FILE="${PROXY_DIR}/proxy.pid"
PRIVATE_KEY="${TESLA_PRIVATE_KEY:-${CONFIG_DIR}/drobnik.com.tesla.private-key.pem}"

WAKE_WAIT_SECONDS="${WAKE_WAIT_SECONDS:-60}"
RETRY_COUNT="${RETRY_COUNT:-3}"
RETRY_SLEEP_SECONDS="${RETRY_SLEEP_SECONDS:-20}"

log() {
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

subtract_minutes() {
  local time="$1"
  local mins_to_sub="$2"
  local hour min
  hour="$(echo "$time" | cut -d: -f1)"
  min="$(echo "$time" | cut -d: -f2)"

  min=$((10#$min - mins_to_sub))
  while [ $min -lt 0 ]; do
    min=$((min + 60))
    hour=$((10#$hour - 1))
  done

  printf "%02d:%02d" "$hour" "$min"
}

time_to_minutes() {
  local time="$1"
  local hour min
  hour="$(echo "$time" | cut -d: -f1)"
  min="$(echo "$time" | cut -d: -f2)"
  echo $((10#$hour * 60 + 10#$min))
}

ensure_proxy_running() {
  # Only relevant when base_url in config points to localhost proxy.
  if [ ! -f "$CONFIG_FILE" ]; then
    return 0
  fi

  local base_url
  base_url="$($PYTHON_BIN - "$CONFIG_FILE" <<'PY' 2>/dev/null || true
import json,sys
p=sys.argv[1]
try:
  j=json.load(open(p))
  print(j.get('base_url',''))
except Exception:
  pass
PY
)"

  if [[ "$base_url" != https://localhost:* ]]; then
    return 0
  fi

  # Check pid file
  if [ -f "$PROXY_PID_FILE" ]; then
    local pid
    pid="$(cat "$PROXY_PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ps -p "$pid" >/dev/null 2>&1; then
      return 0
    fi
  fi

  if [ ! -f "$PRIVATE_KEY" ]; then
    log "Proxy not running and private key missing: $PRIVATE_KEY"
    return 1
  fi

  log "Starting tesla-http-proxy (base_url=$base_url)"
  bash "${SCRIPTS_DIR}/start_proxy.sh" "$PRIVATE_KEY" >> "$LOG_FILE" 2>&1
}

with_retry() {
  local n=1
  while true; do
    if "$@"; then
      return 0
    fi
    if [ $n -ge "$RETRY_COUNT" ]; then
      return 1
    fi
    log "Command failed (attempt $n/$RETRY_COUNT). Retrying after wake + ${RETRY_SLEEP_SECONDS}s…"
    $PYTHON_BIN "${SCRIPTS_DIR}/command.py" wake >> "$LOG_FILE" 2>&1 || true
    sleep "$RETRY_SLEEP_SECONDS"
    n=$((n+1))
  done
}

main() {
  if [ ! -x "$ICALBUDDY_BIN" ]; then
    log "Error: icalBuddy not found at $ICALBUDDY_BIN"
    exit 1
  fi

  # Get all school events today.
  # icalBuddy outputs times like "    07:50 - 13:25" on their own line after the event title
  local school_times
  school_times="$($ICALBUDDY_BIN -nc -ic "Elise,Erika" -n eventsToday 2>/dev/null \
    | grep -A5 -i "schule" \
    | grep -E '^\s+[0-9]{2}:[0-9]{2} - [0-9]{2}:[0-9]{2}' \
    | sed -E 's/.*([0-9]{2}:[0-9]{2}) - ([0-9]{2}:[0-9]{2}).*/\1 \2/' \
    || true)"

  if [ -z "$school_times" ]; then
    log "No school today, skipping precondition"
    exit 0
  fi

  # Collect all start and end times
  local earliest_start=""
  local earliest_start_mins=9999
  local end_times=""

  while read -r start end; do
    if [ -n "${start:-}" ] && [ -n "${end:-}" ]; then
      local start_mins
      start_mins="$(time_to_minutes "$start")"

      if [ "$start_mins" -lt "$earliest_start_mins" ]; then
        earliest_start_mins="$start_mins"
        earliest_start="$start"
      fi

      # Collect unique end times
      if [[ ! " $end_times " =~ " $end " ]]; then
        end_times="$end_times $end"
      fi
    fi
  done <<< "$school_times"

  if [ -z "$earliest_start" ]; then
    log "Could not parse school times"
    exit 1
  fi

  # Home coordinates from config
  local home_lat="" home_lon=""
  if [ -f "$CONFIG_FILE" ]; then
    read -r home_lat home_lon <<< "$($PYTHON_BIN - <<PY 2>/dev/null || true
import json
c=json.load(open('$CONFIG_FILE'))
print(f"{c.get('home_lat','')} {c.get('home_lon','')}")
PY
)"
  fi

  if [ -z "$home_lat" ] || [ -z "$home_lon" ]; then
    log "Error: home_lat and home_lon must be set in $CONFIG_FILE"
    exit 1
  fi

  local today
  today="$(date +%a | tr '[:upper:]' '[:lower:]')"

  log "School starts: $earliest_start, ends:$end_times"
  log "Today is $today"

  ensure_proxy_running

  # Refresh token first
  log "Refreshing token…"
  $PYTHON_BIN "${SCRIPTS_DIR}/auth.py" refresh >> "$LOG_FILE" 2>&1 || true

  # Wake vehicle and wait a bit
  log "Waking vehicle…"
  $PYTHON_BIN "${SCRIPTS_DIR}/command.py" wake >> "$LOG_FILE" 2>&1 || true
  log "Waiting ${WAKE_WAIT_SECONDS}s for vehicle to wake…"
  sleep "$WAKE_WAIT_SECONDS"

  # Remove prior one-time schedules (Tesla does not auto-expire them)
  log "Removing prior one-time precondition schedules (if any)…"
  local list_json
  list_json="$($PYTHON_BIN "${SCRIPTS_DIR}/command.py" precondition list --json 2>>"$LOG_FILE" || echo '{}')"

  local one_time_ids
  one_time_ids="$(printf '%s' "$list_json" | $PYTHON_BIN - <<'PY'
import json,sys
try:
    j=json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)
ids=[]
for s in j.get('precondition_schedules', []):
    if s.get('one_time') and 'id' in s:
        ids.append(str(s['id']))
w=j.get('preconditioning_schedule_window')
if isinstance(w, dict) and w.get('one_time') and 'id' in w:
    if str(w['id']) not in ids:
        ids.append(str(w['id']))
print(' '.join(ids))
PY
)"

  if [ -n "$one_time_ids" ]; then
    for id in $one_time_ids; do
      log "Removing one-time schedule id $id"
      $PYTHON_BIN "${SCRIPTS_DIR}/command.py" precondition remove --id "$id" >> "$LOG_FILE" 2>&1 || true
    done
  else
    log "No prior one-time schedules found"
  fi

  local precond_start
  precond_start="$(subtract_minutes "$earliest_start" 10)"

  log "Scheduling morning precondition for $precond_start ($today)"
  with_retry $PYTHON_BIN "${SCRIPTS_DIR}/command.py" precondition add -t "$precond_start" --one-time --lat "$home_lat" --lon "$home_lon" -d "$today" >> "$LOG_FILE" 2>&1

  for end_time in $end_times; do
    local precond_end
    precond_end="$(subtract_minutes "$end_time" 10)"
    log "Scheduling pickup precondition for $precond_end (school ends $end_time, $today)"
    with_retry $PYTHON_BIN "${SCRIPTS_DIR}/command.py" precondition add -t "$precond_end" --one-time --lat "$home_lat" --lon "$home_lon" -d "$today" >> "$LOG_FILE" 2>&1
  done

  log "Done"
}

main "$@"
