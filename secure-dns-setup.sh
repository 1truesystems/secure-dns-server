#!/bin/bash
###############################################################################
#  Secure DNS Server - Automated Setup Script
#  AdGuard Home + Tailscale on Raspberry Pi
#
#  Usage:
#    chmod +x secure-dns-setup.sh
#    sudo ./secure-dns-setup.sh
#
#  What this script does:
#    1. Sets static IP on the Pi
#    2. Installs & configures AdGuard Home (DNS filtering)
#    3. Installs & configures Tailscale (VPN for remote DNS access)
#    4. Applies 14 professional security filter lists (1.6M+ rules)
#    5. Configures security-focused upstream DNS (Quad9, Cloudflare Security)
#
#  After running, you need to:
#    - Add the Pi to your Tailscale network (link will be shown)
#    - Set router DHCP DNS to this Pi's IP
#    - Set Tailscale DNS to this Pi's Tailscale IP (for remote access)
###############################################################################

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# ─── Root check ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root: sudo $0"
fi

# ─── Banner ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "============================================="
echo "   Secure DNS Server - Automated Setup"
echo "   AdGuard Home + Tailscale + 14 Filters"
echo "============================================="
echo -e "${NC}"

# ─── Detect Network Info ─────────────────────────────────────────────────────
DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
CURRENT_IP=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
CURRENT_GATEWAY=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
CURRENT_SUBNET=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+/\d+' | head -1)

info "Detected network interface: ${BOLD}$DEFAULT_IFACE${NC}"
info "Detected IP: ${BOLD}$CURRENT_IP${NC}"
info "Detected gateway: ${BOLD}$CURRENT_GATEWAY${NC}"

# ─── User Input ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}--- Network Configuration ---${NC}"
read -rp "Static IP for this Pi [$CURRENT_IP]: " STATIC_IP
STATIC_IP=${STATIC_IP:-$CURRENT_IP}

read -rp "Gateway [$CURRENT_GATEWAY]: " GATEWAY
GATEWAY=${GATEWAY:-$CURRENT_GATEWAY}

read -rp "Subnet mask in CIDR (e.g., /24) [/24]: " CIDR
CIDR=${CIDR:-/24}

echo ""
echo -e "${BOLD}--- AdGuard Home Credentials ---${NC}"
read -rp "Admin username [admin]: " AGH_USER
AGH_USER=${AGH_USER:-admin}

while true; do
    read -rsp "Admin password: " AGH_PASS
    echo ""
    if [[ -z "$AGH_PASS" ]]; then
        warn "Password cannot be empty"
    else
        break
    fi
done

echo ""
echo -e "${BOLD}--- Summary ---${NC}"
echo "  Interface:    $DEFAULT_IFACE"
echo "  Static IP:    $STATIC_IP$CIDR"
echo "  Gateway:      $GATEWAY"
echo "  Admin user:   $AGH_USER"
echo ""
read -rp "Proceed with installation? [Y/n]: " CONFIRM
CONFIRM=${CONFIRM:-Y}
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# ─── Step 1: System Update ───────────────────────────────────────────────────
log "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# ─── Step 2: Install Dependencies ────────────────────────────────────────────
log "Installing dependencies..."
apt-get install -y -qq curl wget python3 net-tools dnsutils > /dev/null 2>&1
# Install bcrypt - try apt first, fallback to pip
apt-get install -y -qq python3-bcrypt > /dev/null 2>&1 || {
    warn "python3-bcrypt not in apt, installing via pip..."
    apt-get install -y -qq python3-pip > /dev/null 2>&1
    pip3 install bcrypt --break-system-packages > /dev/null 2>&1 || pip3 install bcrypt > /dev/null 2>&1
}

# ─── Step 3: Set Static IP ───────────────────────────────────────────────────
log "Configuring static IP: $STATIC_IP$CIDR on $DEFAULT_IFACE..."

# Detect connection name
CONN_NAME=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | grep "$DEFAULT_IFACE" | cut -d: -f1)

if [[ -n "$CONN_NAME" ]]; then
    nmcli connection modify "$CONN_NAME" \
        ipv4.method manual \
        ipv4.addresses "${STATIC_IP}${CIDR}" \
        ipv4.gateway "$GATEWAY" \
        ipv4.dns "1.1.1.1 8.8.8.8"
    nmcli connection up "$CONN_NAME" > /dev/null 2>&1 || true
    log "Static IP set via NetworkManager"
elif command -v dhcpcd &>/dev/null; then
    # Fallback: dhcpcd (older Raspberry Pi OS)
    cat >> /etc/dhcpcd.conf <<DHCP

# Static IP - configured by secure-dns-setup
interface $DEFAULT_IFACE
static ip_address=${STATIC_IP}${CIDR}
static routers=$GATEWAY
static domain_name_servers=1.1.1.1 8.8.8.8
DHCP
    log "Static IP set via dhcpcd"
else
    warn "Could not detect network manager. Please set static IP manually."
fi

# ─── Step 4: Disable systemd-resolved (if running) ──────────────────────────
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    log "Disabling systemd-resolved to free port 53..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    # Point resolv.conf to real DNS temporarily
    rm -f /etc/resolv.conf
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
fi

# Also check if port 53 is in use
if ss -tlnp | grep -q ':53 ' 2>/dev/null; then
    warn "Port 53 is in use. Attempting to free it..."
    # Stop common DNS services
    for svc in dnsmasq bind9 named; do
        systemctl stop "$svc" 2>/dev/null && systemctl disable "$svc" 2>/dev/null || true
    done
fi

# ─── Step 4.5: Open Firewall Ports (if ufw is active) ────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    log "Opening firewall ports (DNS:53, HTTP:80, Tailscale:41641)..."
    ufw allow 53/tcp > /dev/null 2>&1
    ufw allow 53/udp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 41641/udp > /dev/null 2>&1
    log "Firewall rules added"
fi

# ─── Step 5: Install AdGuard Home ────────────────────────────────────────────
log "Installing AdGuard Home..."

if [[ -d /opt/AdGuardHome ]]; then
    warn "AdGuard Home already installed at /opt/AdGuardHome. Backing up config..."
    cp /opt/AdGuardHome/AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml.bak 2>/dev/null || true
else
    curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
fi

# Wait for AdGuard to start
sleep 3
systemctl stop AdGuardHome 2>/dev/null || true

# ─── Step 6: Generate Password Hash ─────────────────────────────────────────
log "Generating password hash..."

AGH_HASH=$(python3 -c "
import bcrypt
password = '''${AGH_PASS}'''
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10))
print(hashed.decode())
")

if [[ -z "$AGH_HASH" ]]; then
    err "Failed to generate password hash. Is python3-bcrypt installed?"
fi

# ─── Step 7: Write AdGuard Home Configuration ────────────────────────────────
log "Writing AdGuard Home configuration (14 filters, 1.6M+ rules)..."

cat > /opt/AdGuardHome/AdGuardHome.yaml << ADGUARD_CONFIG
http:
  pprof:
    port: 6060
    enabled: false
  address: 0.0.0.0:80
  session_ttl: 720h
users:
  - name: ${AGH_USER}
    password: ${AGH_HASH}
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: false
  ratelimit: 300
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
    - https://dns10.quad9.net/dns-query
    - https://security.cloudflare-dns.com/dns-query
    - https://1.1.1.2/dns-query
    - https://8.8.8.8/dns-query
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
    - 8.8.8.8
  fallback_dns:
    - https://dns10.quad9.net/dns-query
    - https://security.cloudflare-dns.com/dns-query
    - https://8.8.4.4/dns-query
  upstream_mode: parallel
  fastest_timeout: 0s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
  cache_enabled: true
  cache_size: 8388608
  cache_ttl_min: 300
  cache_ttl_max: 0
  cache_optimistic: true
  cache_optimistic_answer_ttl: 30s
  cache_optimistic_max_age: 12h
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: ""
  bootstrap_prefer_ipv6: false
  upstream_timeout: 30s
  private_networks: []
  use_private_ptr_resolvers: true
  local_ptr_upstreams: []
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: false
  serve_plain_dns: true
  hostsfile_enabled: true
  pending_requests:
    enabled: true
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 784
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  allow_unencrypted_doh: false
  certificate_chain: ""
  private_key: ""
  certificate_path: ""
  private_key_path: ""
  strict_sni_check: false
querylog:
  dir_path: ""
  ignored: []
  interval: 24h
  size_memory: 1000
  enabled: true
  file_enabled: true
statistics:
  dir_path: ""
  ignored: []
  interval: 24h
  enabled: true
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://adaway.org/hosts.txt
    name: AdAway Default Blocklist
    id: 2
  - enabled: true
    url: https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts
    name: Steven Black hosts (ads+malware+fakenews+gambling+porn)
    id: 3
  - enabled: true
    url: https://big.oisd.nl
    name: OISD Blocklist Full
    id: 4
  - enabled: true
    url: https://phishing.army/download/phishing_army_blocklist_extended.txt
    name: Phishing Army Extended
    id: 5
  - enabled: true
    url: https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt
    name: NoCoin Filter List (cryptomining)
    id: 6
  - enabled: true
    url: https://someonewhocares.org/hosts/zero/hosts
    name: Dan Pollock's hosts
    id: 7
  - enabled: true
    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt
    name: Hagezi Threat Intelligence Feeds
    id: 8
  - enabled: true
    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt
    name: Hagezi Multi PRO++
    id: 9
  - enabled: true
    url: https://urlhaus.abuse.ch/downloads/hostfile/
    name: URLhaus Malicious URL Blocklist
    id: 10
  - enabled: true
    url: https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt
    name: Scam Blocklist by DurableNapkin
    id: 11
  - enabled: true
    url: https://threatfox.abuse.ch/downloads/hostfile/
    name: ThreatFox IOCs
    id: 12
  - enabled: true
    url: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt
    name: Hagezi DNS-over-HTTPS/TLS Bypass
    id: 13
  - enabled: true
    url: https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt
    name: Phishing URL Blocklist (PhishTank)
    id: 14
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  local_domain_name: lan
  dhcpv4:
    gateway_ip: ""
    subnet_mask: ""
    range_start: ""
    range_end: ""
    lease_duration: 86400
    icmp_timeout_msec: 1000
    options: []
  dhcpv6:
    range_start: ""
    lease_duration: 86400
    ra_slaac_only: false
    ra_allow_slaac: false
filtering:
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_services:
    schedule:
      time_zone: Local
    ids: []
  protection_disabled_until: null
  safe_search:
    enabled: false
    bing: true
    duckduckgo: true
    ecosia: true
    google: true
    pixabay: true
    yandex: true
    youtube: true
  blocking_mode: default
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  rewrites: []
  safe_fs_patterns: []
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  filters_update_interval: 24
  blocked_response_ttl: 10
  filtering_enabled: true
  rewrites_enabled: true
  parental_enabled: false
  safebrowsing_enabled: true
  protection_enabled: true
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent: []
log:
  enabled: true
  file: ""
  max_backups: 0
  max_size: 100
  max_age: 3
  compress: false
  local_time: false
  verbose: false
os:
  group: ""
  user: ""
  rlimit_nofile: 0
schema_version: 32
ADGUARD_CONFIG

# ─── Step 8: Start AdGuard Home ──────────────────────────────────────────────
log "Starting AdGuard Home..."
systemctl enable AdGuardHome
systemctl start AdGuardHome

# Wait for DNS to become available
log "Waiting for DNS to initialize (loading 1.6M+ rules)..."
for i in $(seq 1 30); do
    if dig @127.0.0.1 google.com +short +time=2 > /dev/null 2>&1; then
        log "AdGuard Home DNS is ready!"
        break
    fi
    sleep 2
    if [[ $i -eq 30 ]]; then
        warn "DNS taking longer than expected. Check: systemctl status AdGuardHome"
    fi
done

# ─── Step 9: Install Tailscale ───────────────────────────────────────────────
log "Installing Tailscale..."

if command -v tailscale &>/dev/null; then
    info "Tailscale already installed"
else
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# ─── Step 10: Configure Tailscale ────────────────────────────────────────────
log "Starting Tailscale..."
systemctl enable tailscaled
systemctl start tailscaled

# Don't let Tailscale override Pi's DNS (it's a DNS server itself)
tailscale set --accept-dns=false 2>/dev/null || true

# Check if already authenticated
if tailscale status > /dev/null 2>&1; then
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "N/A")
    info "Tailscale already authenticated. IP: $TAILSCALE_IP"
else
    echo ""
    echo -e "${YELLOW}=============================================${NC}"
    echo -e "${YELLOW}  Tailscale needs authentication!${NC}"
    echo -e "${YELLOW}  Open the link below in your browser:${NC}"
    echo -e "${YELLOW}=============================================${NC}"
    echo ""
    tailscale up --accept-dns=false 2>&1
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "N/A")
fi

# ─── Step 11: Verify Everything ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}=============================================${NC}"
echo -e "${BOLD}   Verification${NC}"
echo -e "${BOLD}=============================================${NC}"

# Check AdGuard
if systemctl is-active --quiet AdGuardHome; then
    log "AdGuard Home: RUNNING"
else
    err "AdGuard Home: FAILED"
fi

# Check DNS resolution
if dig @127.0.0.1 google.com +short +time=3 > /dev/null 2>&1; then
    log "DNS Resolution: WORKING"
else
    warn "DNS Resolution: NOT READY (may need more time to load filters)"
fi

# Check ad blocking
AD_RESULT=$(dig @127.0.0.1 ads.google.com +short +time=3 2>/dev/null)
if [[ "$AD_RESULT" == "0.0.0.0" ]] || [[ "$AD_RESULT" == "127.0.0.1" ]]; then
    log "Ad Blocking: ACTIVE"
else
    warn "Ad Blocking: filters may still be loading"
fi

# Check Tailscale
if systemctl is-active --quiet tailscaled; then
    log "Tailscale: RUNNING"
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "not authenticated")
    info "Tailscale IP: $TAILSCALE_IP"
else
    warn "Tailscale: NOT RUNNING"
fi

# ─── Done ────────────────────────────────────────────────────────────────────
LOCAL_IP=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "N/A")

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}   Setup Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "${BOLD}Server Info:${NC}"
echo "  Local IP:      $LOCAL_IP"
echo "  Tailscale IP:  $TAILSCALE_IP"
echo "  AdGuard Panel: http://$LOCAL_IP"
echo "  Admin User:    $AGH_USER"
echo ""
echo -e "${BOLD}What you need to do now:${NC}"
echo ""
echo -e "  ${CYAN}1. Router DHCP DNS:${NC}"
echo "     Primary DNS:   $LOCAL_IP"
echo "     Secondary DNS: 1.1.1.1"
echo ""
echo -e "  ${CYAN}2. Tailscale DNS (for remote access):${NC}"
echo "     Go to: https://login.tailscale.com/admin/dns"
echo "     Add Global Nameserver: $TAILSCALE_IP"
echo "     Enable 'Override local DNS'"
echo ""
echo -e "${BOLD}Security Features:${NC}"
echo "  - 14 filter lists (1.6M+ rules)"
echo "  - DNS-over-HTTPS upstream (Quad9 + Cloudflare Security)"
echo "  - DNSSEC enabled"
echo "  - Safe Browsing enabled"
echo "  - Parallel DNS mode (fastest response)"
echo "  - 8MB DNS cache with optimistic caching"
echo "  - Blocks: ads, trackers, malware, phishing, scams,"
echo "    cryptomining, fake news, gambling, stalkerware, DoH bypass"
echo ""
echo -e "${GREEN}Done! Your network is now protected.${NC}"
