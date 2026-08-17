#!/bin/sh
#
# dhcp-mac-check.sh — detect devices using a static IP to evade DHCP-based
# firewall policy on OpenWrt.
#
# Two modes:
#
#   (default)     List every active host whose live IP/MAC does not match a
#                 DHCP lease or reservation. Good for a default-ALLOW firewall
#                 where an unknown static IP escapes per-host BLOCK rules.
#                   OK / NO-LEASE / MISMATCH
#
#   --firewall    Cross-reference against the firewall's enabled ACCEPT
#                 lan->wan rules (a default-DENY "internet allowlist", e.g.
#                 parental control). Only flags a real bypass: an IP that the
#                 firewall ALLOWS to the internet, currently live, whose DHCP
#                 lease/reservation belongs to a DIFFERENT MAC (impersonation)
#                 or to NO MAC at all (unmanaged static on an allowed IP).
#                   IMPERSONATION / STATIC-ALLOW
#
# Sources:
#   /tmp/dhcp.leases       MAC the router actually handed an IP to
#   uci dhcp host entries  admin-configured static reservations (allowed)
#   uci firewall rules     enabled ACCEPT lan->wan src_ip allowlist
#   ip neigh (ARP table)   who is actually on the wire right now
#
# BusyBox ash / POSIX sh only. No arrays, no bashisms.
#
# Exit status: 0 = clean, 1 = suspect(s) found, 2 = usage/error.

set -u

# ---------------------------------------------------------------------------
# Args / config
# ---------------------------------------------------------------------------
MODE="default"
usage() {
	cat <<EOF
Usage: $0 [--firewall] [--help]

  (no args)    Report active hosts with no/mismatched DHCP lease.
  --firewall   Only report devices bypassing the internet allowlist:
               an enabled-ACCEPT IP in use by the wrong/no MAC.

Env overrides:
  LAN_IFACES       interfaces to scan (default: auto-detect LAN bridge)
  WHITELIST_FILE   ignore-list of MACs/IPs (default: /etc/dhcp-mac-check.whitelist)
  LEASES_FILE      lease db (default: /tmp/dhcp.leases)
EOF
}
for arg in "$@"; do
	case "$arg" in
		--firewall|-f) MODE="firewall" ;;
		--help|-h)     usage; exit 0 ;;
		*) echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
	esac
done

LAN_IFACES="${LAN_IFACES:-}"
WHITELIST_FILE="${WHITELIST_FILE:-/etc/dhcp-mac-check.whitelist}"
LEASES_FILE="${LEASES_FILE:-/tmp/dhcp.leases}"

if [ -z "$LAN_IFACES" ]; then
	dev="$(uci -q get network.lan.device 2>/dev/null)"
	[ -z "$dev" ] && dev="$(uci -q get network.lan.ifname 2>/dev/null)"
	[ -z "$dev" ] && dev="br-lan"
	LAN_IFACES="$dev"
fi

# ---------------------------------------------------------------------------
# Build a single tagged stream; one awk pass does the comparison.
# Tags: LEASE / RESV / ROUTER / ROUTERMAC / NEIGH / WHITE / FWALLOW
# ---------------------------------------------------------------------------
{
	# 1) DHCP leases:  <expiry> <mac> <ip> <hostname> <clientid>
	if [ -r "$LEASES_FILE" ]; then
		awk '{ if (NF >= 3) print "LEASE", $2, $3 }' "$LEASES_FILE"
	fi

	# 2) Static reservations (admin-intended, allowed).
	if command -v uci >/dev/null 2>&1; then
		uci -q show dhcp 2>/dev/null | awk -F. '
			/\.mac=/ { split($0, a, "="); gsub(/['"'"'"]/, "", a[2]); mac[$2]=a[2] }
			/\.ip=/  { split($0, a, "="); gsub(/['"'"'"]/, "", a[2]); ip[$2]=a[2] }
			END { for (s in mac) if (s in ip) print "RESV", mac[s], ip[s] }
		'
	fi

	# 3) Router-owned IPs/MACs -> never flag self.
	for ifc in $LAN_IFACES; do
		ip -o -4 addr show dev "$ifc" 2>/dev/null | \
			awk '{ split($4, a, "/"); print "ROUTER", a[1] }'
		ip -o link show dev "$ifc" 2>/dev/null | \
			awk '{ for (i=1;i<=NF;i++) if ($i=="link/ether") print "ROUTERMAC", $(i+1) }'
	done

	# 4) Live neighbour (ARP) table.
	for ifc in $LAN_IFACES; do
		ip -4 neigh show dev "$ifc" 2>/dev/null | \
			awk -v ifc="$ifc" '
				/lladdr/ {
					ipaddr=$1; state=$NF; mac=""
					for (i=1;i<=NF;i++) if ($i=="lladdr") mac=$(i+1)
					if (mac != "" && state != "FAILED" && state != "INCOMPLETE")
						print "NEIGH", ipaddr, mac, ifc, state
				}'
	done

	# 5) Whitelist.
	if [ -r "$WHITELIST_FILE" ]; then
		awk '!/^[[:space:]]*#/ && NF { print "WHITE", tolower($1) }' "$WHITELIST_FILE"
	fi

	# 6) Firewall allowlist: enabled ACCEPT lan->wan src_ip entries.
	#    Emitted as: FWALLOW <ip> <rule name...>
	if [ "$MODE" = "firewall" ] && command -v uci >/dev/null 2>&1; then
		i=0
		while uci -q get firewall.@rule[$i] >/dev/null 2>&1; do
			if [ "$(uci -q get firewall.@rule[$i].src)"    = "lan" ] && \
			   [ "$(uci -q get firewall.@rule[$i].dest)"   = "wan" ] && \
			   [ "$(uci -q get firewall.@rule[$i].target)" = "ACCEPT" ] && \
			   [ "$(uci -q get firewall.@rule[$i].enabled)" != "0" ]; then
				name="$(uci -q get firewall.@rule[$i].name)"
				[ -z "$name" ] && name="rule$i"
				for sip in $(uci -q get firewall.@rule[$i].src_ip 2>/dev/null); do
					echo "FWALLOW $sip $name"
				done
			fi
			i=$((i+1))
		done
	fi
} | awk -v mode="$MODE" '
	function norm(s) { return tolower(s) }

	$1 == "LEASE"     { m=norm($2); leaseip[m]=$3;  leasemac_byip[$3]=m }
	$1 == "RESV"      { m=norm($2); resvip[m]=$3;   resvmac_byip[$3]=m  }
	$1 == "ROUTER"    { routerip[$2]        = 1 }
	$1 == "ROUTERMAC" { routermac[norm($2)] = 1 }
	$1 == "WHITE"     { white[$2]           = 1 }
	$1 == "NEIGH" {
		n++; nip[n]=$2; nmac[n]=norm($3); nifc[n]=$4; nstate[n]=$5
		livemac[$2]=norm($3); liveifc[$2]=$4   # keyed by IP for firewall mode
	}
	$1 == "FWALLOW" {
		ip=$2; name=""
		for (i=3; i<=NF; i++) { if (i>3) name = name " "; name = name $i }
		if (!(ip in fwallow)) fwallow[ip]=name
	}

	END {
		if (mode == "firewall") { fw_report(); exit (fw_suspects > 0 ? 1 : 0) }
		else                    { def_report(); exit (def_suspects > 0 ? 1 : 0) }
	}

	# -- default mode: lease/reservation consistency for every active host ----
	function def_report(  i, ipaddr, mac, ifc, known, src, verdict, detail) {
		printf "%-16s %-18s %-9s %-8s %s\n", "LIVE-IP","MAC","IFACE","VERDICT","DETAIL"
		printf "%-16s %-18s %-9s %-8s %s\n", "----------------","------------------","---------","--------","------"
		def_suspects = 0
		for (i = 1; i <= n; i++) {
			ipaddr=nip[i]; mac=nmac[i]; ifc=nifc[i]
			if (ipaddr in routerip)  continue
			if (mac in routermac)    continue
			if (mac in white)        continue
			if (ipaddr in white)     continue
			known=""; src=""
			if (mac in leaseip)      { known=leaseip[mac]; src="lease" }
			else if (mac in resvip)  { known=resvip[mac];  src="reservation" }
			if (known == "") {
				verdict="NO-LEASE"; detail="active MAC has no DHCP lease (static IP suspected)"; def_suspects++
			} else if (known != ipaddr) {
				verdict="MISMATCH"; detail=src" says "known" but host is using "ipaddr; def_suspects++
			} else continue
			printf "%-16s %-18s %-9s %-8s %s\n", ipaddr, mac, ifc, verdict, detail
		}
		if (def_suspects == 0)
			print "\nNo suspects: every active host matches a DHCP lease or reservation."
		else
			printf "\n%d suspect host(s) found.\n", def_suspects
	}

	# -- firewall mode: who is exploiting the internet allowlist ---------------
	function fw_report(  ip, lm, ifc, owner, src, verdict, detail, blocked, ok) {
		printf "%-16s %-18s %-9s %-14s %-14s %s\n", "LIVE-IP","MAC","IFACE","ALLOW-RULE","VERDICT","DETAIL"
		printf "%-16s %-18s %-9s %-14s %-14s %s\n", "----------------","------------------","---------","--------------","--------------","------"
		fw_suspects = 0; ok = 0
		for (ip in fwallow) {
			if (ip in routerip) continue
			lm = livemac[ip]
			if (lm == "")       continue          # allowed IP not currently in use
			if (lm in white || ip in white) continue
			ifc = liveifc[ip]
			owner=""; src=""
			if (ip in leasemac_byip)      { owner=leasemac_byip[ip]; src="lease" }
			else if (ip in resvmac_byip)  { owner=resvmac_byip[ip];  src="reservation" }

			if (owner == "") {
				verdict="STATIC-ALLOW"
				detail="allowed IP in use with NO lease/reservation (unmanaged static)"
				fw_suspects++
			} else if (owner != lm) {
				verdict="IMPERSONATION"
				detail=src" for "ip" is "owner" but "lm" is using it (static IP bypass)"
				fw_suspects++
			} else { ok++; continue }            # correct owner on an allowed IP

			printf "%-16s %-18s %-9s %-14s %-14s %s\n", ip, lm, ifc, fwallow[ip], verdict, detail
		}

		# Informational: active static hosts that the allowlist simply DROPs.
		blocked = 0
		for (i = 1; i <= n; i++) {
			ipaddr=nip[i]; mac=nmac[i]
			if (ipaddr in routerip || mac in routermac) continue
			if (mac in white || ipaddr in white)        continue
			if (ipaddr in fwallow)                       continue   # handled above
			if (mac in leaseip || mac in resvip)         continue   # normal DHCP host
			blocked++
		}

		if (fw_suspects == 0)
			print "\nNo firewall bypass: every allowed+live IP is held by its correct DHCP owner."
		else
			printf "\n%d device(s) bypassing the internet allowlist.\n", fw_suspects
		printf "(%d allowed host(s) verified OK; %d active static host(s) are blocked by \"block all\", not bypassing.)\n", ok, blocked
	}
'
