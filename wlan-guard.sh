#!/bin/sh
#
# wlan-guard.sh — block Wi-Fi clients that are using an IPv4 address no DHCP
# lease or reservation grants them AND are actively transferring, then unblock
# them once they leave or go back to their own address.
#
# Runs from cron / dnsmasq hotplug. Each run reconciles one firewall block
# list against the network:
#
#   candidate  = a (MAC, IP) pair: MAC associated to our AP(s), holding an
#                IPv4 that its lease/reservation does not grant it
#   BLOCK      = the unauthorized IPv4 address(es) of a candidate that is
#                transferring faster than RATE_THRESHOLD_KB
#   keep       = an already-blocked IP whose hold has not run out yet
#   UNBLOCK    = a blocked IP or MAC whose BLOCK_HOLD_HOURS hold has expired
#   BLOCK MAC  = the candidate's own MAC, dropped outright (BLOCK_MACS=1), so
#                one rule covers every address it is holding at once
#
# The test is on the PAIR, not the MAC. Holding a lease does not entitle a
# device to any other address: a MAC leased .50 that is sitting on static .155
# is exactly as unauthorized on .155 as a MAC with no lease at all. That is the
# evasion this exists to stop — take a lease once, then move to an address some
# other firewall rule allows. (dhcp-mac-check.sh reports the same condition as
# MISMATCH; this script is what enforces it.)
#
# Enforcement is keyed on the client's IPv4 address, not its MAC. Devices that
# randomize their MAC get a fresh identity on every reconnect, so a MAC-keyed
# block cannot hold them; the static IP a squatter actually uses to reach the
# network is the stable handle, so that is what we drop. A device sitting on
# the address it was granted is never touched, MAC-random or not.
#
# The transfer-rate test is the BLOCK trigger only, and time is the only thing
# that releases a block. Both directions of evidence decay once an IP is
# dropped: its measured rate falls to ~0 because we are dropping its traffic,
# and its neighbour entry goes stale or is garbage-collected because the block
# stops the very packets that kept the entry fresh. Gating either *keeping* the
# block on that evidence makes blocks flap — observed in the field as block,
# release three minutes later, re-block on the next burst. So a block simply
# stands for BLOCK_HOLD_HOURS and is then released; if the address is still
# being misused, the next run blocks it again.
#
# A block therefore ends on its own only when the hold runs out. An operator can
# also end one early: `wlan-guard.sh unblock <ip|mac|all>` drops the rule and the
# ledger entry with it. That releases and nothing more — the next run judges the
# network from scratch, so a device still sitting on an address it was not
# granted is blocked again within one cron tick. Whitelist its MAC to exempt it
# for good.
#
# Authorized pairs = active DHCP leases (/tmp/dhcp.leases: the MAC the router
# actually handed each IP to) plus static reservations (uci dhcp 'host' with
# both mac and ip). On a busy network most devices are dynamic-lease holders,
# so trusting leases is what makes this target real address misuse rather than
# every non-reserved phone. Toggle with ALLOW_ACTIVE_LEASES.
#
# Trusted on ANY address, never candidates: the whitelist file, plus 'host'
# reservations that name a mac but pin no ip — there the admin vouched for the
# device without choosing its address.
#
# Transfer rate is measured from conntrack byte counters (nf_conntrack_acct
# must be on) summed over the device's current IP(s), sampled across
# SAMPLE_SECONDS. A device with no IP / no routed traffic measures 0.
#
# Enforcement backend is auto-detected:
#   * nftables (fw4, OpenWrt 22.03+): table 'inet wlan_guard', @blocked set of
#     IPv4 addresses, dropped by 'ip saddr' in both input and forward.
#   * iptables (fw3, OpenWrt 21.02):  chain WLAN_GUARD jumped from INPUT and
#     FORWARD, dropping by source IPv4. IPv4 only, so no ip6tables chain.
# Either way a blocked client loses router access and internet access.
#
# NOTE: upgrading from a MAC-keyed build? The set/chain type changed, so run
# `wlan-guard.sh flush` once before deploying this to drop the old state.
#
# Every block and unblock is optionally published to MQTT with a UTC timestamp,
# under MQTT_TOPIC (default openwrt/wlan-guard) with a 'blocked'/'unblocked'
# leaf. Off unless a broker host is configured; see MQTT_* below.
#
# Site config is read from /etc/wlan-guard.conf if present (see that file).
#
# BusyBox ash / POSIX sh only. No arrays, no bashisms.
#
# Usage:  wlan-guard.sh [run|status|list|unblock TARGET...|flush] [--dry-run]
#   run      (default) measure + reconcile the block list.
#   status   show counts + the live firewall ruleset (no measuring).
#   list     print the IPs currently blocked.
#   unblock  release blocks now: IPv4 address(es), MAC(s), or the word 'all'.
#            The hold is dropped along with the block, so the next run is free
#            to block again if the device is still misusing an address.
#   flush    tear down all wlan-guard firewall state (unblock everyone).
#   --dry-run / -n   measure and print decisions, change nothing.
#
# Exit: 0 ok, 2 usage/environment error.

set -u

[ -r /etc/wlan-guard.conf ] && . /etc/wlan-guard.conf

# ---------------------------------------------------------------------------
# Config (env / /etc/wlan-guard.conf overridable)
# ---------------------------------------------------------------------------
TAG="wlan-guard"
V4CHAIN="WLAN_GUARD"                                   # iptables chain name
NFT_TABLE="wlan_guard"                                 # nft table name
NFT_SET="blocked"                                      # ipv4_addr set of blocked IPs
NFT_MACSET="blocked_macs"                              # ether_addr set of blocked MACs

WLAN_IFACES="${WLAN_IFACES:-}"                         # blank = auto-detect AP ifaces
WHITELIST_FILE="${WHITELIST_FILE:-/etc/wlan-guard.whitelist}"
LEASES_FILE="${LEASES_FILE:-/tmp/dhcp.leases}"
ALLOW_ACTIVE_LEASES="${ALLOW_ACTIVE_LEASES:-1}"        # 1 = leases count as "known"
RATE_THRESHOLD_KB="${RATE_THRESHOLD_KB:-30}"           # block only if kB/s exceeds this
SAMPLE_SECONDS="${SAMPLE_SECONDS:-4}"                  # throughput sample window
CT_FILE="${CT_FILE:-/proc/net/nf_conntrack}"

# How long a block is held once placed. Time is the ONLY release criterion.
# Presence evidence decays while an IP is dropped -- the block stops the very
# traffic that keeps the neighbour entry fresh -- so releasing a block on
# "device looks gone" made blocks flap: blocked, released a few minutes later,
# re-blocked on the next burst. If the address is still being misused when the
# hold expires, the next run simply blocks it again.
BLOCK_HOLD_HOURS="${BLOCK_HOLD_HOURS:-3}"
STATE_FILE="${STATE_FILE:-/tmp/wlan-guard.blocks}"     # one "<key> <epoch>" line

# Also drop the offender's MAC outright, not just the address(es) it is abusing.
# A MAC block stops the device in one rule however many addresses it holds, and
# it spares the rightful owners of those addresses. It is not a replacement for
# the address blocks: a device that randomizes its MAC while keeping a static
# IP is caught by the address block and would walk straight past a MAC block,
# so both are applied. Requires the xt_mac match (iptables) or an ether_addr
# set (nft); if that is missing the address block still stands on its own.
BLOCK_MACS="${BLOCK_MACS:-1}"

# MQTT (optional): publish a message every time an IP is blocked or unblocked.
# No-op unless MQTT_HOST is set and mosquitto_pub (mosquitto-client) is
# installed, so leaving it unset changes nothing. Two topics are published:
# <MQTT_TOPIC>/blocked and <MQTT_TOPIC>/unblocked. MQTT_TOPIC defaults to
# <MQTT_BASE>/wlan-guard; set it directly to control the whole prefix.
MQTT_HOST="${MQTT_HOST:-}"                             # broker host; blank = MQTT off
MQTT_PORT="${MQTT_PORT:-1883}"
MQTT_BASE="${MQTT_BASE:-openwrt}"                      # base topic
MQTT_TOPIC="${MQTT_TOPIC:-$MQTT_BASE/wlan-guard}"      # full topic prefix; <prefix>/<action>
MQTT_USER="${MQTT_USER:-}"                             # optional broker username
MQTT_PASS="${MQTT_PASS:-}"                             # optional broker password
MQTT_QOS="${MQTT_QOS:-0}"
MQTT_RETAIN="${MQTT_RETAIN:-0}"                        # 1 = retain last state per topic

MAC_RE='([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
IPV4_RE='([0-9]{1,3}\.){3}[0-9]{1,3}'

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
CMD="run"
DRYRUN=0
TARGETS=""                     # unblock operands, in the order given
for arg in "$@"; do
	case "$arg" in
		run|status|list|flush|unblock) CMD="$arg" ;;
		--dry-run|-n)          DRYRUN=1 ;;
		# print the header comment block, however long it grows
		--help|-h)             awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
		-*) echo "$TAG: unknown option: $arg" >&2; exit 2 ;;
		# Bare words mean nothing to run/status/list/flush; they are unblock's
		# operands, so hold them and let the dispatch reject strays.
		*) TARGETS="$TARGETS $arg" ;;
	esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
die()  { echo "$TAG: $*" >&2; exit 2; }
log()  { logger -t "$TAG" -- "$*" 2>/dev/null; [ -t 2 ] && echo "$TAG: $*" >&2; }

# Only 'unblock' takes operands. Rejecting them everywhere else keeps a typo
# ("wlan-guard.sh run 192.168.4.5") from looking like it did something.
no_targets() { [ -z "$TARGETS" ] || die "unknown argument:$TARGETS"; }

# Publish a block/unblock state change to MQTT. Silent no-op if MQTT is not
# configured or mosquitto_pub is missing; a broker error is logged, never fatal.
#   $1 = action (blocked|unblocked)   $2 = ip or MAC   $3 = reason
#   $4 = payload field name for $2, "ip" (default) or "mac"
# Payload is JSON with an ISO-8601 UTC timestamp taken at the moment of change.
mqtt_pub() {
	[ -n "$MQTT_HOST" ] && have mosquitto_pub || return 0
	# Saved before the `set --` below rebuilds the argument list and takes
	# $1/$2/$3 with it.
	_action="$1"; _ip="$2"; _reason="$3"; _field="${4:-ip}"
	_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	_topic="$MQTT_TOPIC/$_action"
	_payload="{\"action\":\"$_action\",\"$_field\":\"$_ip\",\"reason\":\"$_reason\",\"time\":\"$_ts\",\"router\":\"$(uname -n)\"}"
	set -- -h "$MQTT_HOST" -p "$MQTT_PORT" -q "$MQTT_QOS" -t "$_topic" -m "$_payload"
	[ "$MQTT_RETAIN" = 1 ] && set -- "$@" -r
	[ -n "$MQTT_USER" ] && set -- "$@" -u "$MQTT_USER"
	[ -n "$MQTT_PASS" ] && set -- "$@" -P "$MQTT_PASS"
	mosquitto_pub "$@" 2>/dev/null || log "mqtt publish failed ($_action $_ip)"
}

# Set subtraction on line-files. BusyBox grep treats an EMPTY -f pattern file
# as "match every line" (the opposite of GNU/BSD), hence the -s guard.
minus() { if [ -s "$2" ]; then grep -vxF -f "$2" "$1"; else cat "$1"; fi; }  # $1 \ $2

# AP-mode wireless interfaces (Master mode only, so we never read a STA/mesh
# uplink and mistake the upstream AP for a client).
wlan_ifaces() {
	if [ -n "$WLAN_IFACES" ]; then printf '%s\n' $WLAN_IFACES; return; fi
	for i in $(iwinfo 2>/dev/null | awk '/ESSID/ {print $1}'); do
		iwinfo "$i" info 2>/dev/null | grep -q 'Mode: Master' && echo "$i"
	done
}

associated_macs() {
	for i in $(wlan_ifaces); do iwinfo "$i" assoclist 2>/dev/null; done \
		| grep -oE "$MAC_RE" | tr 'A-F' 'a-f'
}

# Authorized "<mac> <ip>" pairs, one per line: an address is only legitimate on
# the MAC it was granted to. Sources are the static reservations (uci dhcp
# 'host' entries carrying both mac and ip) and, if enabled, the active leases.
# A 'host' section may list several MACs for one ip; each gets its own pair.
known_pairs() {
	uci -q show dhcp 2>/dev/null | sed "s/'//g" | awk -F. '
		/\.mac=/ { split($0, a, "="); mac[$2] = a[2] }
		/\.ip=/  { split($0, a, "="); ip[$2]  = a[2] }
		END {
			for (s in mac) {
				if (!(s in ip)) continue          # no ip pinned -> see trusted_macs
				n = split(mac[s], m, /[ \t]+/)
				for (i = 1; i <= n; i++)
					if (m[i] != "") print tolower(m[i]), ip[s]
			}
		}
	'
	if [ "$ALLOW_ACTIVE_LEASES" = 1 ] && [ -r "$LEASES_FILE" ]; then
		awk 'NF >= 3 { print tolower($2), $3 }' "$LEASES_FILE"
	fi
}

# MACs trusted on ANY address, so never candidates: whitelist entries, plus
# 'host' reservations that name a mac but pin no ip (the admin vouched for the
# device, not for an address — blocking it off-lease would be a surprise).
trusted_macs() {
	[ -r "$WHITELIST_FILE" ] && awk '!/^[[:space:]]*#/ && NF {print $1}' "$WHITELIST_FILE"
	uci -q show dhcp 2>/dev/null | sed "s/'//g" | awk -F. '
		/\.mac=/ { split($0, a, "="); mac[$2] = a[2] }
		/\.ip=/  { ip[$2] = 1 }
		END { for (s in mac) if (!(s in ip)) print mac[s] }
	' | tr ' \t' '\n\n'
}

# All current IPs (v4/v6) for a MAC, from the neighbour table. Matched on the
# lladdr field, not the whole line, so a MAC can never match inside an address.
# FAILED / INCOMPLETE entries are skipped: nothing is reachable at them.
ips_for_mac() {
	m="$(printf '%s' "$1" | tr 'A-F' 'a-f')"
	ip neigh show 2>/dev/null | awk -v m="$m" '
		/lladdr/ {
			state = $NF
			if (state == "FAILED" || state == "INCOMPLETE") next
			for (i = 1; i <= NF; i++)
				if ($i == "lladdr" && tolower($(i+1)) == m) { print $1; next }
		}'
}

# Just the IPv4 address(es) a MAC currently holds — what we actually block on.
ipv4s_for_mac() { ips_for_mac "$1" | grep -oE "^$IPV4_RE$"; }

# The IPv4 address(es) a MAC holds that no lease/reservation grants it — the
# ones we are entitled to drop.  $1 = lowercase MAC, $2 = file of known pairs.
unauthorized_ipv4s_for_mac() {
	_m="$1"; _pairs="$2"
	ipv4s_for_mac "$_m" | sort -u | while IFS= read -r _a; do
		[ -n "$_a" ] || continue
		grep -qxF "$_m $_a" "$_pairs" && continue
		echo "$_a"
	done
}

# Sum of conntrack bytes (both directions) for flows touching an IP.
ct_bytes_for_ip() {
	ipesc="$(printf '%s' "$1" | sed 's/[.]/\\./g')"
	grep -E "(src|dst)=$ipesc " "$CT_FILE" 2>/dev/null \
		| grep -oE 'bytes=[0-9]+' | awk -F= '{s+=$2} END {print s+0}'
}

# --- firewall backend -------------------------------------------------------
BACKEND=""
fw_detect() {
	if have nft && nft list ruleset >/dev/null 2>&1; then
		BACKEND=nft
	elif have iptables; then
		BACKEND=iptables
	else
		die "no firewall backend: need nft or iptables"
	fi
}

fw_ensure() {
	case "$BACKEND" in
	nft)
		nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && return 0
		nft -f - <<EOF
table inet $NFT_TABLE {
	set $NFT_SET { type ipv4_addr ; }
	set $NFT_MACSET { type ether_addr ; }
	chain input   { type filter hook input   priority -1; policy accept; udp dport 67 return; ip saddr @$NFT_SET drop; ether saddr @$NFT_MACSET drop }
	chain forward { type filter hook forward priority -1; policy accept; udp dport 67 return; ip saddr @$NFT_SET drop; ether saddr @$NFT_MACSET drop }
}
EOF
		;;
	iptables)
		# IPv4 only: we drop by source IPv4 address, so no ip6tables chain.
		iptables -w -N "$V4CHAIN" 2>/dev/null
		# DHCP stays open even for a blocked device, so a host that is merely
		# misconfigured can still get a proper lease and stop being a candidate
		# on its own. RETURN, not ACCEPT: the rest of the firewall still applies.
		iptables -w -C "$V4CHAIN" -p udp --dport 67 -j RETURN 2>/dev/null \
			|| iptables -w -I "$V4CHAIN" 1 -p udp --dport 67 -j RETURN
		iptables -w -C INPUT   -j "$V4CHAIN" 2>/dev/null || iptables -w -I INPUT   1 -j "$V4CHAIN"
		iptables -w -C FORWARD -j "$V4CHAIN" 2>/dev/null || iptables -w -I FORWARD 1 -j "$V4CHAIN"
		;;
	esac
}

fw_current() {
	case "$BACKEND" in
	nft)      nft list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null | grep -oE "$IPV4_RE" ;;
	iptables) iptables -w -S "$V4CHAIN" 2>/dev/null | grep -oE "$IPV4_RE" ;;
	esac
}

fw_block() {
	case "$BACKEND" in
	nft) nft add element inet "$NFT_TABLE" "$NFT_SET" "{ $1 }" ;;
	iptables)
		iptables -w -C "$V4CHAIN" -s "$1" -j DROP 2>/dev/null \
			|| iptables -w -A "$V4CHAIN" -s "$1" -j DROP ;;
	esac
}

fw_unblock() {
	case "$BACKEND" in
	nft) nft delete element inet "$NFT_TABLE" "$NFT_SET" "{ $1 }" 2>/dev/null ;;
	iptables)
		iptables -w -D "$V4CHAIN" -s "$1" -j DROP 2>/dev/null ;;
	esac
}

# Same three operations, keyed on the MAC instead of the address.
fw_current_macs() {
	case "$BACKEND" in
	nft)      nft list set inet "$NFT_TABLE" "$NFT_MACSET" 2>/dev/null \
			| grep -oiE "$MAC_RE" | tr 'A-F' 'a-f' ;;
	iptables) iptables -w -S "$V4CHAIN" 2>/dev/null \
			| sed -n 's/.*--mac-source \([0-9A-Fa-f:]\{17\}\).*/\1/p' | tr 'A-F' 'a-f' ;;
	esac
}

fw_block_mac() {
	case "$BACKEND" in
	nft) nft add element inet "$NFT_TABLE" "$NFT_MACSET" "{ $1 }" ;;
	iptables)
		iptables -w -C "$V4CHAIN" -m mac --mac-source "$1" -j DROP 2>/dev/null \
			|| iptables -w -A "$V4CHAIN" -m mac --mac-source "$1" -j DROP ;;
	esac
}

fw_unblock_mac() {
	case "$BACKEND" in
	nft) nft delete element inet "$NFT_TABLE" "$NFT_MACSET" "{ $1 }" 2>/dev/null ;;
	iptables)
		iptables -w -D "$V4CHAIN" -m mac --mac-source "$1" -j DROP 2>/dev/null ;;
	esac
}

fw_flush() {
	case "$BACKEND" in
	nft) nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && nft delete table inet "$NFT_TABLE" ;;
	iptables)
		for X in iptables ip6tables; do
			have "$X" || continue
			"$X" -w -D INPUT   -j "$V4CHAIN" 2>/dev/null
			"$X" -w -D FORWARD -j "$V4CHAIN" 2>/dev/null
			"$X" -w -F "$V4CHAIN" 2>/dev/null
			"$X" -w -X "$V4CHAIN" 2>/dev/null
		done ;;
	esac
}

# ---------------------------------------------------------------------------
# Block ledger: when each IP was blocked, so the hold can outlive the evidence
# that triggered it. Kept in /tmp because the firewall rules it describes are
# themselves lost on reboot, so the two always expire together.
# ---------------------------------------------------------------------------
state_get() {                  # $1 = ip -> epoch it was blocked ("" if unknown)
	[ -r "$STATE_FILE" ] || return 0
	awk -v ip="$1" '$1 == ip { t = $2 } END { if (t != "") print t }' "$STATE_FILE"
}

state_set() {                  # $1 = ip, $2 = epoch
	_new="$STATE_FILE.$$"
	{ [ -r "$STATE_FILE" ] && awk -v ip="$1" '$1 != ip' "$STATE_FILE"
	  echo "$1 $2"; } > "$_new" && mv "$_new" "$STATE_FILE"
}

state_del() {                  # $1 = ip
	[ -r "$STATE_FILE" ] || return 0
	_new="$STATE_FILE.$$"
	awk -v ip="$1" '$1 != ip' "$STATE_FILE" > "$_new" && mv "$_new" "$STATE_FILE"
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
cmd_flush() {
	fw_detect
	fw_current | sort -u | while IFS= read -r ip; do
		[ -n "$ip" ] || continue
		mqtt_pub unblocked "$ip" "manual flush"
	done
	fw_current_macs | sort -u | while IFS= read -r mc; do
		[ -n "$mc" ] || continue
		mqtt_pub unblocked "$mc" "manual flush" mac
	done
	fw_flush
	rm -f "$STATE_FILE"
	log "flushed: all wlan-guard firewall state removed, everyone unblocked"
}

cmd_list() { fw_detect; fw_current | sort -u; }

# Manual release. The hold is how a block normally ends, but an operator needs a
# way to take one back now: the rightful owner reclaiming an address that is
# still dropped from the squatter's turn on it, or simply a call to overrule.
# Takes any mix of IPv4 addresses and MACs, or 'all' for everything blocked.
cmd_unblock() {                # "$@" = ip | mac | all
	fw_detect
	[ "$#" -gt 0 ] || die "unblock needs an IPv4 address, a MAC, or 'all'"

	if [ "$1" = all ]; then
		[ "$#" = 1 ] || die "'all' takes no other arguments"
		# Expand before anything is removed, so what is reported is what was
		# actually released. Unquoted on purpose: this is a word list.
		set -- $(fw_current | sort -u) $(fw_current_macs | sort -u)
		[ "$#" -gt 0 ] || { log "unblock all: nothing is blocked"; return 0; }
	fi

	released=0
	for t in "$@"; do
		[ "$t" = all ] && die "'all' cannot be mixed with addresses"
		if echo "$t" | grep -qE "^$IPV4_RE\$"; then
			if ! fw_current | grep -qxF "$t"; then
				log "unblock: $t is not blocked"
				continue
			fi
			if [ "$DRYRUN" = 1 ]; then
				echo "WOULD UNBLOCK $t (manual)"
			else
				fw_unblock "$t" || { log "unblock failed: $t"; continue; }
				state_del "$t"
				log "UNBLOCK $t (manual release)"
				mqtt_pub unblocked "$t" "manual release"
			fi
			released=$((released + 1))
		elif echo "$t" | grep -qE "^$MAC_RE\$"; then
			mc="$(echo "$t" | tr 'A-F' 'a-f')"
			if ! fw_current_macs | grep -qxF "$mc"; then
				log "unblock: MAC $mc is not blocked"
				continue
			fi
			if [ "$DRYRUN" = 1 ]; then
				echo "WOULD UNBLOCK MAC $mc (manual)"
			else
				fw_unblock_mac "$mc" || { log "unblock failed: MAC $mc"; continue; }
				state_del "$mc"
				log "UNBLOCK MAC $mc (manual release)"
				mqtt_pub unblocked "$mc" "manual release" mac
			fi
			released=$((released + 1))
		else
			die "not an IPv4 address or MAC: $t"
		fi
	done

	if [ "$DRYRUN" = 1 ]; then
		log "unblock: would release $released (dry run, nothing changed)"
		return 0
	fi
	[ "$released" -gt 0 ] || return 0

	# An address release does not put a device back on the air while its MAC is
	# still dropped, and vice versa. Report what still stands so a half release
	# does not look like a failed one.
	log "unblock: released $released; still blocked: $(fw_current | sort -u | grep -c .) address(es), $(fw_current_macs | sort -u | grep -c .) MAC(s)"
	if [ -t 2 ]; then
		echo "$TAG: note: the next run re-blocks any device still using an address it" >&2
		echo "$TAG:       was not granted. To exempt it, whitelist its MAC in" >&2
		echo "$TAG:       $WHITELIST_FILE." >&2
	fi
	return 0
}

cmd_status() {
	have iwinfo || die "iwinfo not found"
	fw_detect
	st="$(mktemp -d /tmp/wlan-guard.XXXXXX)" || die "mktemp failed"
	trap 'rm -rf "$st"' EXIT
	associated_macs | sort -u > "$st/assoc"
	known_pairs | awk 'NF >= 2 { print tolower($1), $2 }' | sort -u > "$st/pairs"
	trusted_macs | grep -oiE "$MAC_RE" | tr 'A-F' 'a-f' | sort -u > "$st/trusted"
	minus "$st/assoc" "$st/trusted" | sort -u > "$st/checked"
	: > "$st/cand"
	while IFS= read -r m; do
		[ -n "$m" ] || continue
		bad="$(unauthorized_ipv4s_for_mac "$m" "$st/pairs" | tr '\n' ' ')"
		[ -n "$bad" ] || continue
		echo "$m $bad" >> "$st/cand"
	done < "$st/checked"
	echo "backend       : $BACKEND"
	echo "AP interfaces : $(wlan_ifaces | tr '\n' ' ')"
	echo "associated    : $(grep -c . "$st/assoc")"
	echo "authorized    : $(grep -c . "$st/pairs") mac/ip pair(s) (lease + reservation)"
	echo "trusted       : $(grep -c . "$st/trusted") mac(s) allowed on any address"
	echo "candidates    : $(grep -c . "$st/cand")  (associated, on an address it was not granted)"
	while IFS= read -r line; do
		m="${line%% *}"; ips="${line#* }"
		ipshow="$(echo $ips | tr ' ' ',' | sed 's/,$//')"
		granted="$(awk -v m="$m" '$1 == m { print $2 }' "$st/pairs" \
			| sort -u | tr '\n' ',' | sed 's/,$//')"
		[ -n "$granted" ] || granted="nothing"
		printf '                %s  %s  (granted: %s)\n' "$m" "$ipshow" "$granted"
	done < "$st/cand"
	echo "blocked IPs   : $(fw_current | sort -u | grep -c .)"
	nowsec="$(date +%s)"
	fw_current | sort -u | while IFS= read -r ip; do
		[ -n "$ip" ] || continue
		since="$(state_get "$ip")"
		case "$since" in ''|*[!0-9]*)
			printf '                %s  (not in ledger; hold starts next run)\n' "$ip"
			continue ;;
		esac
		left=$((BLOCK_HOLD_HOURS * 3600 - (nowsec - since)))
		[ "$left" -lt 0 ] && left=0
		printf '                %s  %dh%02dm left of %sh hold\n' \
			"$ip" $((left / 3600)) $(((left % 3600) / 60)) "$BLOCK_HOLD_HOURS"
	done
	if [ "$BLOCK_MACS" = 1 ]; then
		echo "blocked MACs  : $(fw_current_macs | sort -u | grep -c .)"
		fw_current_macs | sort -u | while IFS= read -r mc; do
			[ -n "$mc" ] || continue
			since="$(state_get "$mc")"
			case "$since" in ''|*[!0-9]*)
				printf '                %s  (not in ledger; hold starts next run)\n' "$mc"
				continue ;;
			esac
			left=$((BLOCK_HOLD_HOURS * 3600 - (nowsec - since)))
			[ "$left" -lt 0 ] && left=0
			printf '                %s  %dh%02dm left of %sh hold\n' \
				"$mc" $((left / 3600)) $(((left % 3600) / 60)) "$BLOCK_HOLD_HOURS"
		done
	fi
	echo "rate rule     : block if > ${RATE_THRESHOLD_KB} kB/s over ${SAMPLE_SECONDS}s"
	echo "hold rule     : once blocked, stay blocked ${BLOCK_HOLD_HOURS}h, then release"
	echo "mac rule      : $([ "$BLOCK_MACS" = 1 ] && echo "also drop the offender's MAC" || echo "addresses only")"
	echo "manual        : wlan-guard.sh unblock <ip|mac|all> releases early"
	echo
	case "$BACKEND" in
	nft)      nft list table inet "$NFT_TABLE" 2>/dev/null || echo "(nft table not installed yet)" ;;
	iptables) iptables -w -S "$V4CHAIN" 2>/dev/null || echo "(iptables chain not installed yet)" ;;
	esac
}

cmd_run() {
	have iwinfo || die "iwinfo not found"
	fw_detect

	tmp="$(mktemp -d /tmp/wlan-guard.XXXXXX)" || die "mktemp failed"
	trap 'rm -rf "$tmp"' EXIT
	: > "$tmp/toblock"      # IPs to newly block this run (rate-triggered)
	: > "$tmp/toblockmac"   # MACs to newly block this run (same trigger)
	: > "$tmp/candip"       # every v4 IP held by an associated MAC not entitled to it
	: > "$tmp/macips"       # "<mac> <v4ip...>" for candidates that hold such an IP

	associated_macs | sort -u > "$tmp/assoc"
	known_pairs | awk 'NF >= 2 { print tolower($1), $2 }' | sort -u > "$tmp/pairs"
	trusted_macs | grep -oiE "$MAC_RE" | tr 'A-F' 'a-f' | sort -u > "$tmp/trusted"
	# Every associated MAC is examined except the any-address trusted ones; what
	# makes it a candidate is the address it holds, not whether we know the MAC.
	minus "$tmp/assoc" "$tmp/trusted" | sort -u > "$tmp/cand"

	[ "$DRYRUN" = 1 ] || fw_ensure
	fw_current | sort -u > "$tmp/current"

	# Resolve each candidate MAC to the IPv4 address(es) it is squatting: the
	# ones no lease or reservation grants it. Those IPs — not the (possibly
	# randomized) MAC — are what we reconcile on, so a device that rotates its
	# MAC but keeps the static IP stays blocked. A MAC that also holds its own
	# leased address keeps that address; only the unauthorized one is dropped.
	while IFS= read -r m; do
		[ -n "$m" ] || continue
		v4="$(unauthorized_ipv4s_for_mac "$m" "$tmp/pairs" | tr '\n' ' ')"
		[ -n "$v4" ] || continue          # only on its own address => nothing to do
		printf '%s\n' $v4 >> "$tmp/candip"
		echo "$m $v4" >> "$tmp/macips"
	done < "$tmp/cand"
	# BusyBox sort has no -o: write via a temp file, or the list leaks to
	# stdout and the original is left undeduplicated.
	sort -u "$tmp/candip" > "$tmp/candip.s" && mv "$tmp/candip.s" "$tmp/candip"

	# Measure a candidate only if it holds at least one IP not already blocked.
	# If one of its addresses is already blocked then the rate test has already
	# fired for this device once, so its MAC is blocked without waiting for
	# another sample -- which it would never produce, because the address block
	# has already stopped its traffic.
	: > "$tmp/measure"
	while IFS= read -r line; do
		m="${line%% *}"; ips="${line#* }"
		fresh=0; seenblocked=0
		for ip in $ips; do
			if grep -qxF "$ip" "$tmp/current"; then seenblocked=1; else fresh=1; fi
		done
		[ "$fresh" = 1 ] && echo "$line" >> "$tmp/measure"
		if [ "$seenblocked" = 1 ] && [ "$BLOCK_MACS" = 1 ]; then
			echo "$m|already blocked on an address it was not granted" >> "$tmp/toblockmac"
		fi
	done < "$tmp/macips"

	if [ -s "$tmp/measure" ]; then
		# sample t1 for every candidate, one shared window, then t2
		: > "$tmp/b1"
		while IFS= read -r line; do
			m="${line%% *}"; ips="${line#* }"
			s=0; for ip in $ips; do s=$((s + $(ct_bytes_for_ip "$ip"))); done
			echo "$m $s $ips" >> "$tmp/b1"
		done < "$tmp/measure"

		sleep "$SAMPLE_SECONDS"

		while IFS= read -r line; do
			m="${line%% *}"; rest="${line#* }"; s1="${rest%% *}"; ips="${rest#* }"
			s2=0; for ip in $ips; do s2=$((s2 + $(ct_bytes_for_ip "$ip"))); done
			d=$((s2 - s1)); [ "$d" -lt 0 ] && d=0
			rate=$((d / 1024 / SAMPLE_SECONDS))
			ipshow="$(echo $ips | tr ' ' ',' | sed 's/,$//')"
			if [ "$rate" -gt "$RATE_THRESHOLD_KB" ]; then
				for ip in $ips; do echo "$ip" >> "$tmp/toblock"; done
				[ "$BLOCK_MACS" = 1 ] && \
					echo "$m|holding an address it was not granted, active >${RATE_THRESHOLD_KB}kB/s" \
						>> "$tmp/toblockmac"
				[ "$DRYRUN" = 1 ] && echo "$TAG: WOULD BLOCK $m [$ipshow]  ${rate}kB/s"
			else
				[ "$DRYRUN" = 1 ] && echo "$TAG: skip $m [$ipshow]  ${rate}kB/s <= ${RATE_THRESHOLD_KB}"
			fi
		done < "$tmp/b1"
	fi

	# desired = (blocked IPs whose hold has not expired yet) + newly triggered.
	now="$(date +%s)"
	hold=$((BLOCK_HOLD_HOURS * 3600))
	: > "$tmp/keep"
	while IFS= read -r ip; do
		[ -n "$ip" ] || continue
		since="$(state_get "$ip")"
		case "$since" in ''|*[!0-9]*) since="" ;; esac
		if [ -z "$since" ]; then
			# Blocked but not in the ledger (state file lost, or the rule was
			# added by hand): adopt it now so it still gets a bounded life.
			[ "$DRYRUN" = 1 ] || state_set "$ip" "$now"
			echo "$ip" >> "$tmp/keep"
		elif [ $((now - since)) -lt "$hold" ]; then
			echo "$ip" >> "$tmp/keep"
		fi
	done < "$tmp/current"
	cat "$tmp/keep" "$tmp/toblock" 2>/dev/null | sort -u > "$tmp/desired"

	minus "$tmp/desired" "$tmp/current" > "$tmp/toadd"   # new blocks
	minus "$tmp/current" "$tmp/desired" > "$tmp/todel"   # unblocks

	added=0; removed=0
	while IFS= read -r ip; do
		[ -n "$ip" ] || continue
		if [ "$DRYRUN" = 1 ]; then :; else
			reason="address not granted to this device, active >${RATE_THRESHOLD_KB}kB/s"
			fw_block "$ip" && { state_set "$ip" "$now"; log "BLOCK $ip ($reason)"
				added=$((added+1)); mqtt_pub blocked "$ip" "$reason"; }
		fi
	done < "$tmp/toadd"

	while IFS= read -r ip; do
		[ -n "$ip" ] || continue
		why="${BLOCK_HOLD_HOURS}h hold expired, giving the address another chance"
		if [ "$DRYRUN" = 1 ]; then echo "$TAG: WOULD UNBLOCK $ip ($why)"; else
			fw_unblock "$ip" && { state_del "$ip"; log "UNBLOCK $ip ($why)"
				removed=$((removed+1)); mqtt_pub unblocked "$ip" "$why"; }
		fi
	done < "$tmp/todel"

	# --- the same reconcile, keyed on MAC ---------------------------------
	if [ "$BLOCK_MACS" = 1 ]; then
		fw_current_macs | sort -u > "$tmp/curmac"
		: > "$tmp/keepmac"
		while IFS= read -r mc; do
			[ -n "$mc" ] || continue
			since="$(state_get "$mc")"
			case "$since" in ''|*[!0-9]*) since="" ;; esac
			if [ -z "$since" ]; then
				[ "$DRYRUN" = 1 ] || state_set "$mc" "$now"
				echo "$mc" >> "$tmp/keepmac"
			elif [ $((now - since)) -lt "$hold" ]; then
				echo "$mc" >> "$tmp/keepmac"
			fi
		done < "$tmp/curmac"
		{ cat "$tmp/keepmac"; cut -d'|' -f1 "$tmp/toblockmac"; } 2>/dev/null \
			| sort -u > "$tmp/desiredmac"
		minus "$tmp/desiredmac" "$tmp/curmac" > "$tmp/toaddmac"
		minus "$tmp/curmac" "$tmp/desiredmac" > "$tmp/todelmac"

		while IFS= read -r mc; do
			[ -n "$mc" ] || continue
			reason="$(awk -F'|' -v m="$mc" '$1 == m { print $2; exit }' "$tmp/toblockmac")"
			[ -n "$reason" ] || reason="holding an address it was not granted"
			if [ "$DRYRUN" = 1 ]; then echo "$TAG: WOULD BLOCK MAC $mc ($reason)"; else
				if fw_block_mac "$mc"; then
					state_set "$mc" "$now"; log "BLOCK MAC $mc ($reason)"
					added=$((added+1)); mqtt_pub blocked "$mc" "$reason" mac
				else
					log "mac block failed for $mc (no xt_mac / ether_addr set?); address block still stands"
				fi
			fi
		done < "$tmp/toaddmac"

		while IFS= read -r mc; do
			[ -n "$mc" ] || continue
			why="${BLOCK_HOLD_HOURS}h hold expired, giving the device another chance"
			if [ "$DRYRUN" = 1 ]; then echo "$TAG: WOULD UNBLOCK MAC $mc ($why)"; else
				fw_unblock_mac "$mc" && { state_del "$mc"; log "UNBLOCK MAC $mc ($why)"
					removed=$((removed+1)); mqtt_pub unblocked "$mc" "$why" mac; }
			fi
		done < "$tmp/todelmac"
	fi

	[ "$DRYRUN" = 1 ] && return 0
	{ [ "$added" -gt 0 ] || [ "$removed" -gt 0 ]; } && \
		log "reconcile: +$added blocked, -$removed unblocked"
	return 0
}

# ---------------------------------------------------------------------------
case "$CMD" in
	run)     no_targets; cmd_run ;;
	status)  no_targets; cmd_status ;;
	list)    no_targets; cmd_list ;;
	flush)   no_targets; cmd_flush ;;
	# Unquoted on purpose: the operands are a word list of addresses/MACs.
	unblock) cmd_unblock $TARGETS ;;
esac
