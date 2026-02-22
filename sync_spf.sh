#!/bin/sh
PORT=${INCOMING_SMTP_PORT:-25}
SLEEP_TIME=${SPF_CHECK_INTERVAL:-3600}
SPF_DOMAIN=${WHITELISTED_SPF:-_spf.google.com}
DNS_SERVER=${DNS_SERVER:-8.8.8.8}
BRIDGE_INTERFACE=${INVERSEPROXY_BRIDGE_INTERFACE:-inv_shared_br}
COMMENT_PREFIX="MAILGATE_SPF"

[ -z "$BRIDGE_INTERFACE" ] && { echo "ERROR: Bridge not set"; exit 1; }

# --- Function: Cleanup on Exit ---
cleanup() {
    echo -e "\nStopping... Cleaning up all rules for port $PORT" >&2
    iptables -S DOCKER-USER | grep "dport $PORT" | grep "$COMMENT_PREFIX" | sed 's/-A/-D/' | while read line; do
        iptables $line 2>/dev/null
    done
    exit 0
}

trap cleanup INT TERM

echo "Starting Mailgate Gatekeeper for port $PORT..."

# --- Function: Recursive SPF Resolver ---
fetch_spf_ips() {
    local domain="$1"
    local found_ips=""
    local record=$(nslookup -type=txt "$domain" "$DNS_SERVER" 2>/dev/null | grep "v=spf1")
    
    # 1. Extract direct ip4 blocks
    echo "Processing SPF record for $domain" >&2
    echo "Raw SPF record: $record" >&2
    local direct=$(echo "$record" | tr ' ' '\n' | grep "ip4:" | cut -d: -f2 | tr -d '"')
    found_ips="$found_ips $direct"
    echo "With IPs: $direct" >&2
    
    # 2. Extract includes and recurse
    local includes=$(echo "$record" | tr ' ' '\n' | grep "include:" | cut -d: -f2 | tr -d '"')
    echo "Found includes: $includes" >&2
    for inc in $includes; do
        # We call the function again for the nested domain
        found_ips="$found_ips $(fetch_spf_ips "$inc")"
    done
    
    echo "$found_ips"
}

# --- Function: Update Firewall Rules ---
update_firewall() {
    local spf_ips="$1"
    local run_id=$(date +%s)
    local full_comment="${COMMENT_PREFIX}_${run_id}"

    # Verify our bridge exists before touching iptables
    if ! ip link show "$BRIDGE_INTERFACE" > /dev/null 2>&1; then
        echo "ERROR: Interface $BRIDGE_INTERFACE not found!" >&2
        return 1
    fi

    echo "$(date): Refreshing SPF based whitelisting" >&2

    iptables -A DOCKER-USER -p tcp --dport "$PORT" -m comment --comment "$full_comment" -j DROP

    # Allow SPF Ranges
    for ip in $spf_ips; do
        if [ -n "$ip" ]; then
            iptables -I DOCKER-USER -p tcp --dport "$PORT" -s "$ip" -m comment --comment "$full_comment" -j RETURN
        fi
    done

    # Allow Loopback and Bridge
    iptables -I DOCKER-USER -p tcp --dport "$PORT" -i lo -m comment --comment "$full_comment" -j RETURN
    iptables -I DOCKER-USER -p tcp --dport "$PORT" -i "$BRIDGE_INTERFACE" -m comment --comment "$full_comment" -j RETURN

    # Find all rules for this port that don't match the current full_comment and delete them
    iptables -S DOCKER-USER | grep "dport $PORT" | grep "$COMMENT_PREFIX" | grep -v "$full_comment" | sed 's/-A/-D/' | while read line; do
        iptables $line 2>/dev/null
    done
    
    echo "Update complete. Rules swapped atomically." >&2
}

# --- Main Loop ---
while true; do
    # Fetch and clean up the list
    RAW_LIST=$(fetch_spf_ips "$SPF_DOMAIN")
    CLEAN_LIST=$(echo "$RAW_LIST" | tr -s ' ' | xargs)

    if [ -z "$CLEAN_LIST" ]; then
        echo "DNS Error: No IPs found. Keeping current rules. Will retry in 5m..."
        sleep 300
    else
        update_firewall "$CLEAN_LIST"
        echo "Whitelisted IPs from SPF checkupdated. Next sync in ${SLEEP_TIME}s."
        sleep "$SLEEP_TIME" & wait $!
    fi
done