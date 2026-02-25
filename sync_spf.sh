#!/bin/sh
PORT=${WATCHED_PORT:-25}
# Note that BRIDGE_INTERFACE must be no longer than 15 characters to work with iptables
BRIDGE_INTERFACE=${BRIDGE_INTERFACE:-inv_shared_br}
SPF_DOMAIN=${WHITELISTED_SPF:-_spf.google.com}
REVERSE_DNS_ROOT_DOMAIN=${WHITELISTED_REVERSE_DNS_ROOT_DOMAIN:-unverified-forwarding.1e100.net}
ENABLE_REVERSE_DNS=${ENABLE_REVERSE_DNS:-0}
SLEEP_TIME=${SPF_CHECK_INTERVAL:-86400}
CLEAN_ON_EXIT=${ENABLE_CLEANUP_ON_EXIT:-1}
IP_CACHE_LIMIT=${IP_CACHE_LIMIT:-50}
DNS_SERVER=${DNS_SERVER:-8.8.8.8}
COMMENT_PREFIX=${COMMENT_PREFIX:-MAILGATE_ALLOWED}
SPF_PREFIX="${COMMENT_PREFIX}_SPF"
DYNAMIC_PREFIX="${COMMENT_PREFIX}_DYNAMIC"

[ -z "$BRIDGE_INTERFACE" ] && { echo "ERROR: Bridge not set"; exit 1; }

# --- Function: Configure and Start ulogd ---
start_ulogd() {
    # Create a minimal ulogd config to capture NFLOG group 100 to a file
    cat <<EOF > /etc/ulogd.conf
[global]
logfile="/dev/null"
plugin="/usr/lib/ulogd/ulogd_inppkt_NFLOG.so"
plugin="/usr/lib/ulogd/ulogd_filter_IFINDEX.so"
plugin="/usr/lib/ulogd/ulogd_filter_IP2STR.so"
plugin="/usr/lib/ulogd/ulogd_filter_PRINTPKT.so"
plugin="/usr/lib/ulogd/ulogd_output_LOGEMU.so"
plugin="/usr/lib/ulogd/ulogd_raw2packet_BASE.so"

stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU

[log1]
group=100

[emu1]
file="/var/log/ulogd_syslogemu.log"
sync=1
EOF

    # Create a named pipe (FIFO) to stream logs without saving to disk
    rm -f /var/log/ulogd_syslogemu.log
    mkfifo /var/log/ulogd_syslogemu.log
    
    # Start ulogd as a daemon
    ulogd -d -c /etc/ulogd.conf
}

# --- Function: Cleanup Rules ---
cleanup_rules() {
    local prefix="$1"
    local keep_comment="$2"
    
    # Find all rules matching prefix but NOT matching the current comment
    iptables -S DOCKER-USER | grep "$prefix" | grep -v "$keep_comment" | sed 's/-A/-D/' | while read line; do
        iptables $line 2>/dev/null
    done
}

# --- Function: Apply Allow Rules ---
apply_rules() {
    local ips="$1"
    local comment="$2"
    
    for ip in $ips; do
        if [ -n "$ip" ]; then
            iptables -I DOCKER-USER -p tcp --dport "$PORT" -s "$ip" -m comment --comment "$comment" -j RETURN
        fi
    done
}

# --- Function: Check Reverse DNS ---
check_reverse_dns() {
    local ip="$1"
    local ptr_records=$(dig +short +time=2 +tries=1 -x "$ip")
    
    for record in $ptr_records; do
        # Normalize the record by removing a potential trailing dot.
        local normalized_record=${record%.}
        case "$normalized_record" in
            "$REVERSE_DNS_ROOT_DOMAIN"|*."$REVERSE_DNS_ROOT_DOMAIN")
                return 0
                ;;
        esac
    done
    return 1
}

# --- Function: Recursive SPF Resolver ---
fetch_spf_ips() {
    local domain="$1"
    local found_ips=""
    local record=$(nslookup -type=txt "$domain" "$DNS_SERVER" 2>/dev/null | grep "v=spf1")
    
    # 1. Extract direct ip4 blocks
    local direct=$(echo "$record" | tr ' ' '\n' | grep "ip4:" | cut -d: -f2 | tr -d '"')
    found_ips="$found_ips $direct"
    
    # 2. Extract includes and recurse
    local includes=$(echo "$record" | tr ' ' '\n' | grep "include:" | cut -d: -f2 | tr -d '"')
    for inc in $includes; do
        found_ips="$found_ips $(fetch_spf_ips "$inc")"
    done
    
    echo "$found_ips" | tr -s ' ' | xargs
}

# --- Function: Update Firewall Rules ---
update_firewall() {
    local spf_ips="$1"
    local run_id=$(date +%s)
    local spf_comment="${SPF_PREFIX}_${run_id}"
    local dyn_comment="${DYNAMIC_PREFIX}_${run_id}"

    # Verify our bridge exists before touching iptables
    if ! ip link show "$BRIDGE_INTERFACE" > /dev/null 2>&1; then
        echo "ERROR: Interface $BRIDGE_INTERFACE not found!" >&2
        return 1
    fi

    echo "$(date): Refreshing firewall rules..." >&2

    # 1. Apply SPF Rules
    apply_rules "$spf_ips" "$spf_comment"

    # 2. Recheck and Apply Dynamic Rules
    if [ "$ENABLE_REVERSE_DNS" -eq 1 ]; then
        local current_dyn_ips=$(iptables -S DOCKER-USER | grep "$DYNAMIC_PREFIX" | sed -n 's/.*-s \([0-9.]\+\).*/\1/p' | sort -u)
        local still_good_dns_ips=""
        
        for ip in $current_dyn_ips; do
            if check_reverse_dns "$ip"; then
                still_good_dns_ips="$still_good_dns_ips $ip"
            else
                echo "Dynamic IP $ip no longer validates against $REVERSE_DNS_ROOT_DOMAIN. Dropping." >&2
            fi
        done
        
        if [ -n "$still_good_dns_ips" ]; then
            echo "Refreshing dynamic IPs: $still_good_dns_ips" >&2
            apply_rules "$still_good_dns_ips" "$dyn_comment"
        fi
    fi

    # 3. Apply Static/Tail Rules (Loopback, Bridge, Drop)
    # We have to apply the spf comment so that the cleanup function can identify them as "current" rules to keep
    # This means that each cycle they get reapplied, so that they are always at the top/bottom.
    iptables -I DOCKER-USER -p tcp --dport "$PORT" -i lo -m comment --comment "$spf_comment" -j RETURN
    iptables -I DOCKER-USER -p tcp --dport "$PORT" -i "$BRIDGE_INTERFACE" -m comment --comment "$spf_comment" -j RETURN

    # Log dropped packets to NFLOG group 100 before dropping
    if [ "$ENABLE_REVERSE_DNS" -eq 1 ]; then
        iptables -A DOCKER-USER -p tcp --dport "$PORT" -m comment --comment "$spf_comment" -j NFLOG --nflog-group 100 --nflog-prefix "SPF_DROP"
    fi
    iptables -A DOCKER-USER -p tcp --dport "$PORT" -m comment --comment "$spf_comment" -j DROP
    
    # 4. Cleanup Old Rules
    cleanup_rules "$SPF_PREFIX" "$spf_comment"
    
    if [ "$ENABLE_REVERSE_DNS" -eq 1 ]; then
        cleanup_rules "$DYNAMIC_PREFIX" "$dyn_comment"
    fi
}

# --- Function: Monitor Blocked IPs & Dynamic Whitelist ---
monitor_blocked_ips() {
    start_ulogd

    # Local cache to prevent redundant lookups during packet bursts
    local recent_ips=" "
    local cache_count=0

    # Read from the named pipe. Format: ... SRC=1.2.3.4 DST=...
    cat /var/log/ulogd_syslogemu.log | while read line; do
        # Optimization: Use shell parameter expansion instead of forking grep/cut
        case "$line" in
            *SRC=*)
                src_ip=${line##*SRC=}   # Remove everything before SRC=
                src_ip=${src_ip%% *}    # Remove everything after the IP (space)
                ;;
            *) src_ip="" ;;
        esac

            if [ -n "$src_ip" ]; then
                # Check local cache to avoid processing the same IP repeatedly during a burst
                case "$recent_ips" in
                    *" $src_ip "*) continue ;;
                esac

                # Add to cache
                recent_ips="$recent_ips$src_ip "
                cache_count=$((cache_count + 1))
                if [ "$cache_count" -ge "$IP_CACHE_LIMIT" ]; then
                    recent_ips=" "
                    cache_count=0
                fi

                if check_reverse_dns "$src_ip"; then
                    echo "Dynamic Whitelist: Detected $src_ip. belongs to a subdomain of $REVERSE_DNS_ROOT_DOMAIN. Adding allow rule." >&2
                    iptables -I DOCKER-USER 1 -p tcp --dport "$PORT" -s "$src_ip" -j RETURN -m comment --comment "${DYNAMIC_PREFIX}_$(date +%s)"
                fi
            fi
    done
}


# --- Function: Cleanup on Exit ---
exit_and_cleanup() {
    if [ "$CLEAN_ON_EXIT" -eq 1 ]; then
        echo -e "\nStopping... Cleaning up all rules with prefix $COMMENT_PREFIX" >&2
        cleanup_rules "$COMMENT_PREFIX" "string-that-does-not-match-any-comment-to-ensure-all-rules-are-deleted"
    else
        echo -e "\nStopping... Leaving rules in place as per CLEAN_ON_EXIT=0." >&2
    fi
    killall ulogd 2>/dev/null
    kill $(jobs -p) 2>/dev/null
    exit 0
}

trap exit_and_cleanup INT TERM

# Start the background monitor
if [ "$ENABLE_REVERSE_DNS" -eq 1 ]; then
    monitor_blocked_ips &
fi

# --- Main Loop ---
while true; do
    # Fetch and clean up the list
    SPF_IPS=$(fetch_spf_ips "$SPF_DOMAIN")

    if [ -z "$SPF_IPS" ]; then
        echo "DNS Error: No IPs found. Keeping current rules. Will retry in 5m..."
        sleep 300
    else
        update_firewall "$SPF_IPS"
        echo "Whitelisted IPs from SPF check updated. Next sync in ${SLEEP_TIME}s."
        sleep "$SLEEP_TIME" & wait $!
    fi
done