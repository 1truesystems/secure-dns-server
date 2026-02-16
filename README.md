# Secure DNS Server

Automated setup script for a professional-grade DNS filtering server on Raspberry Pi using **AdGuard Home** + **Tailscale**.

One command installs everything. Protects your entire network from ads, trackers, malware, phishing, scams, and more.

## Features

- **14 filter lists** with **1.6M+ blocking rules**
- **DNS-over-HTTPS** upstream (Quad9, Cloudflare Security, Google)
- **DNSSEC** enabled
- **Google Safe Browsing** integration
- **Parallel DNS mode** (fastest response from multiple servers)
- **8MB DNS cache** with optimistic caching
- **Tailscale VPN** for remote DNS protection (works anywhere)
- **Automatic static IP** configuration

## What Gets Blocked

| Category | Filter |
|---|---|
| Ads & Trackers | AdGuard DNS, OISD Full, Hagezi PRO++, AdAway |
| Malware | Hagezi Threat Intelligence (608K rules), URLhaus, ThreatFox IOCs |
| Phishing | Phishing Army Extended, PhishTank |
| Scams | Scam Blocklist by DurableNapkin |
| Cryptomining | NoCoin Filter List |
| Fake News & Gambling | Steven Black hosts |
| DNS Bypass | Hagezi DoH/DoT Bypass |
| General | Dan Pollock's hosts |

## Upstream DNS Servers (all encrypted DoH)

| Server | Purpose |
|---|---|
| `dns10.quad9.net` | Malware/phishing blocking at DNS level |
| `security.cloudflare-dns.com` | Cloudflare security filter |
| `1.1.1.2` | Cloudflare malware blocking |
| `8.8.8.8` | Google DNS (reliable fallback) |

## Quick Start

### Fresh Install (New Raspberry Pi)

```bash
git clone https://github.com/1truesystems/secure-dns-server.git
cd secure-dns-server
chmod +x secure-dns-setup.sh
sudo ./secure-dns-setup.sh
```

The script will:
1. Ask for static IP and admin password
2. Install & configure AdGuard Home with all filters
3. Install & configure Tailscale
4. Verify everything works
5. Show you what to do next

### Restore from Backup

If you have `adguardhome-full.tar.gz`:

```bash
sudo systemctl stop AdGuardHome
sudo tar xzf adguardhome-full.tar.gz -C /
sudo systemctl start AdGuardHome
```

## After Installation

You only need to do **2 things manually**:

### 1. Router DHCP DNS
Set your router's DHCP DNS server to the Pi's IP:
- **Primary DNS**: `<PI_IP>`
- **Secondary DNS**: `1.1.1.1` (fallback)

This protects all devices on your home network automatically.

### 2. Tailscale DNS (for remote protection)
1. Go to [Tailscale Admin DNS](https://login.tailscale.com/admin/dns)
2. Add Global Nameserver: `<PI_TAILSCALE_IP>`
3. Enable "Override local DNS"

This protects your devices when outside your home network.

## Files

| File | Description |
|---|---|
| `secure-dns-setup.sh` | Automated installer script |
| `AdGuardHome.yaml` | AdGuard Home configuration |
| `README.md` | This file |

## Requirements

- Raspberry Pi (any model with networking)
- Raspberry Pi OS (Debian-based)
- Internet connection
- SSH access

## AdGuard Home Dashboard

After installation, access the dashboard at `http://<PI_IP>` with the credentials you set during setup.

## License

MIT
