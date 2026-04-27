#!/bin/sh
# =============================================================================
# setup.sh — OpenBSD DDoS Shield installer
# =============================================================================
#
# This script installs the pf.conf and relayd.conf from this repository onto
# an OpenBSD system and hardens the network stack via sysctl.
#
# Run as root:
#   doas sh scripts/setup.sh
#
# The script is idempotent: running it again simply refreshes the configs
# and re-applies the sysctl values.
# =============================================================================

set -eu

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
info()  { printf '\033[1;32m[INFO]\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
die()   { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
backup() {
    [ -f "$1" ] && cp -p "$1" "${1}.bak.$(date +%Y%m%d%H%M%S)" && \
        info "Backed up $1"
}

# -----------------------------------------------------------------------------
# Sanity checks
# -----------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "This script must be run as root (use doas)."
[ "$(uname -s)" = "OpenBSD" ] || die "This script is for OpenBSD only."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
ETC_SRC="${REPO_ROOT}/etc"

info "OpenBSD DDoS Shield — setup starting"
info "Repository root: ${REPO_ROOT}"

# -----------------------------------------------------------------------------
# 1. Install pf.conf
# -----------------------------------------------------------------------------
info "Installing pf.conf ..."
backup /etc/pf.conf
cp "${ETC_SRC}/pf.conf" /etc/pf.conf

# Create empty table files if they do not already exist so pfctl can load
# the persistent tables without complaining.
[ -f /etc/pf.whitelist ]   || touch /etc/pf.whitelist
[ -f /etc/pf.ddos_block ]  || touch /etc/pf.ddos_block

info "Checking pf.conf syntax ..."
pfctl -nf /etc/pf.conf || die "pf.conf syntax check failed — aborting."

info "Loading pf.conf ..."
pfctl -f /etc/pf.conf
info "pf rules loaded."

# -----------------------------------------------------------------------------
# 2. Install relayd.conf
# -----------------------------------------------------------------------------
info "Installing relayd.conf ..."
backup /etc/relayd.conf
cp "${ETC_SRC}/relayd.conf" /etc/relayd.conf

info "Checking relayd.conf syntax ..."
relayd -n -f /etc/relayd.conf || die "relayd.conf syntax check failed — aborting."

# -----------------------------------------------------------------------------
# 3. Harden the TCP/IP stack with sysctl
# -----------------------------------------------------------------------------
info "Applying sysctl hardening ..."

# Save current values for reference.
sysctl net.inet.tcp net.inet.ip > /tmp/sysctl_before_ddosshield.txt 2>/dev/null || true

# Enable SYN cookies — the kernel sends a cookie in the SYN-ACK so that a
# half-open connection table cannot be exhausted by a SYN flood.
sysctl net.inet.tcp.syncookies=1

# Drop SYN packets that arrive faster than the kernel can handle them instead
# of queueing them (avoids memory exhaustion under a SYN flood).
sysctl net.inet.tcp.synbuckets=32768

# Maximum number of entries in the SYN cache (half-open connections).
sysctl net.inet.tcp.syncachesize=32768

# Enable RFC 1323 TCP timestamps and window scaling; needed for high-bandwidth
# connections but also used to detect and reject replayed old SYNs.
sysctl net.inet.tcp.rfc1323=1

# Reduce the number of SYN retransmits from the default.  Cuts the time
# a half-open slot is held when the remote never completes the handshake.
sysctl net.inet.tcp.syn_hash_size=1024

# Drop packets with bad IP options (used in some amplification attacks).
sysctl net.inet.ip.options=0

# Do not respond to ICMP broadcast pings (Smurf attack mitigation).
sysctl net.inet.icmp.bmcastecho=0

# Log martian packets (packets with impossible source addresses) for analysis.
sysctl net.inet.ip.redirect=0

# Persist these values across reboots via /etc/sysctl.conf
SYSCTL_CONF=/etc/sysctl.conf
mark_section() {
    grep -q "OpenBSD DDoS Shield" "${SYSCTL_CONF}" 2>/dev/null
}
if ! mark_section; then
    info "Adding sysctl values to ${SYSCTL_CONF} ..."
    cat >> "${SYSCTL_CONF}" << 'EOF'

# --- OpenBSD DDoS Shield ---
net.inet.tcp.syncookies=1
net.inet.tcp.synbuckets=32768
net.inet.tcp.syncachesize=32768
net.inet.tcp.rfc1323=1
net.inet.tcp.syn_hash_size=1024
net.inet.ip.options=0
net.inet.icmp.bmcastecho=0
net.inet.ip.redirect=0
# --- end OpenBSD DDoS Shield ---
EOF
else
    info "sysctl.conf already contains DDoS Shield entries — skipping."
fi

# -----------------------------------------------------------------------------
# 4. Enable and start relayd
# -----------------------------------------------------------------------------
info "Enabling relayd in /etc/rc.conf.local ..."
if ! grep -q "relayd_flags" /etc/rc.conf.local 2>/dev/null; then
    echo 'relayd_flags=""' >> /etc/rc.conf.local
    info "relayd_flags added to /etc/rc.conf.local."
else
    info "relayd already present in /etc/rc.conf.local — skipping."
fi

info "Starting / reloading relayd ..."
if rcctl check relayd > /dev/null 2>&1; then
    rcctl reload relayd && info "relayd reloaded."
else
    rcctl start relayd && info "relayd started."
fi

# -----------------------------------------------------------------------------
# 5. Set up cron job to expire old ddos_block entries
# -----------------------------------------------------------------------------
CRON_MARKER="pfctl -t ddos_block -T expire"
info "Installing cron job to expire stale ddos_block entries ..."
( crontab -l 2>/dev/null | grep -v "${CRON_MARKER}"; \
  echo "*/15 * * * * /sbin/pfctl -t ddos_block -T expire 3600 >/dev/null 2>&1" \
) | crontab -
info "Cron job installed (runs every 15 minutes)."

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo
info "=== OpenBSD DDoS Shield is active ==="
echo
info "Useful commands:"
info "  pfctl -t ddos_block -T show       — list currently blocked IPs"
info "  pfctl -t whitelist  -T add <ip>   — whitelist an IP immediately"
info "  pfctl -t ddos_block -T delete <ip>— unblock an IP immediately"
info "  pfctl -t ddos_block -T expire 0   — flush entire block table"
info "  relayctl show summary             — relayd status overview"
info "  relayctl show hosts               — backend health status"
info "  relayctl show sessions            — active relay sessions"
echo
info "Edit /etc/pf.conf to tune rate limits, then reload with:"
info "  pfctl -f /etc/pf.conf"
