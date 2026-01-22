#!/bin/bash
# Check for school events today and schedule Tesla precondition
# - 10 min before earliest school start
# - 10 min before EACH school end (separate pickup times)
# Run via cron on weekday mornings
#
# Tesla Fleet API reference:
# https://developer.tesla.com/docs/fleet-api/endpoints/vehicle-commands

set -e

SCRIPTS_DIR="$(dirname "$0")"
LOG_FILE="$HOME/.clawdbot/tesla-fleet-api/school-precondition.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

subtract_minutes() {
    local time=$1
    local mins_to_sub=$2
    local hour=$(echo "$time" | cut -d: -f1)
    local min=$(echo "$time" | cut -d: -f2)
    
    min=$((10#$min - mins_to_sub))
    while [ $min -lt 0 ]; do
        min=$((min + 60))
        hour=$((10#$hour - 1))
    done
    
    printf "%02d:%02d" $hour $min
}

time_to_minutes() {
    local time=$1
    local hour=$(echo "$time" | cut -d: -f1)
    local min=$(echo "$time" | cut -d: -f2)
    echo $((10#$hour * 60 + 10#$min))
}

# Get all school events today
# icalBuddy outputs times like "    07:50 - 13:25" on their own line after the event title
SCHOOL_TIMES=$(icalBuddy -nc -ic "Elise,Erika" -n eventsToday 2>/dev/null | grep -A5 -i "schule" | grep -E '^\s+[0-9]{2}:[0-9]{2} - [0-9]{2}:[0-9]{2}' | sed -E 's/.*([0-9]{2}:[0-9]{2}) - ([0-9]{2}:[0-9]{2}).*/\1 \2/')

if [ -z "$SCHOOL_TIMES" ]; then
    log "No school today, skipping precondition"
    exit 0
fi

# Collect all start and end times
EARLIEST_START=""
EARLIEST_START_MINS=9999
END_TIMES=""

while read -r START END; do
    if [ -n "$START" ] && [ -n "$END" ]; then
        START_MINS=$(time_to_minutes "$START")
        
        if [ $START_MINS -lt $EARLIEST_START_MINS ]; then
            EARLIEST_START_MINS=$START_MINS
            EARLIEST_START=$START
        fi
        
        # Collect unique end times
        if [[ ! "$END_TIMES" =~ "$END" ]]; then
            END_TIMES="$END_TIMES $END"
        fi
    fi
done <<< "$SCHOOL_TIMES"

if [ -z "$EARLIEST_START" ]; then
    log "Could not parse school times"
    exit 1
fi

log "School starts: $EARLIEST_START, ends:$END_TIMES"

# Home coordinates: Am Seepark 17, 2421 Kittsee, Austria
HOME_LAT="48.10033"
HOME_LON="17.04217"

# Get current weekday (mon, tue, wed, thu, fri, sat, sun)
TODAY=$(date +%a | tr '[:upper:]' '[:lower:]')
log "Today is $TODAY"

# Refresh token first
log "Refreshing token..."
python3 "$SCRIPTS_DIR/auth.py" refresh >> "$LOG_FILE" 2>&1 || true

# Schedule precondition before school starts (using home coordinates, today only)
PRECOND_START=$(subtract_minutes "$EARLIEST_START" 10)
log "Scheduling morning precondition for $PRECOND_START ($TODAY)"
python3 "$SCRIPTS_DIR/command.py" precondition add -t "$PRECOND_START" --one-time --lat "$HOME_LAT" --lon "$HOME_LON" -d "$TODAY" >> "$LOG_FILE" 2>&1

# Schedule precondition before each school end time
for END_TIME in $END_TIMES; do
    PRECOND_END=$(subtract_minutes "$END_TIME" 10)
    log "Scheduling pickup precondition for $PRECOND_END (school ends $END_TIME, $TODAY)"
    python3 "$SCRIPTS_DIR/command.py" precondition add -t "$PRECOND_END" --one-time --lat "$HOME_LAT" --lon "$HOME_LON" -d "$TODAY" >> "$LOG_FILE" 2>&1
done

log "Done"
