===============================================================================
  SECURE DNS SERVER - FULL BACKUP & INSTALLER
  Created: 2026-02-16
===============================================================================

CONTENTS:
---------
  secure-dns-setup.sh        - Automated installer script (run on new Pi)
  AdGuardHome.yaml            - AdGuard Home configuration file
  adguardhome-full.tar.gz     - Full AdGuard Home directory backup
                                (binary + config + data + filters)
  network-config.txt          - NetworkManager connection config
  tailscale-status.txt        - Tailscale network & devices
  system-info.txt             - Pi system information
  filter-lists-info.txt       - Filter list files info

===============================================================================

OPTION 1: FRESH INSTALL (New Pi)
---------------------------------
  1. Copy secure-dns-setup.sh to the new Pi
  2. Run: sudo ./secure-dns-setup.sh
  3. Follow prompts (IP, password)
  4. Authenticate Tailscale (link will be shown)
  5. Set router DHCP DNS to Pi's IP

OPTION 2: RESTORE FROM BACKUP (Existing Pi)
---------------------------------------------
  1. Copy adguardhome-full.tar.gz to Pi
  2. Run:
       sudo systemctl stop AdGuardHome
       sudo tar xzf adguardhome-full.tar.gz -C /
       sudo systemctl start AdGuardHome
  3. AdGuard Home will be restored with all settings

===============================================================================

ADGUARD HOME:
  Panel:     http://<PI_IP>
  Username:  admin
  Password:  (set during installation)

SECURITY FEATURES:
  - 14 filter lists (1.6M+ rules)
  - DNS-over-HTTPS upstream (Quad9 + Cloudflare Security + Google)
  - DNSSEC enabled
  - Safe Browsing enabled (Google Safe Browsing)
  - Parallel DNS mode
  - 8MB DNS cache with optimistic caching

UPSTREAM DNS SERVERS:
  - https://dns10.quad9.net/dns-query      (malware blocking)
  - https://security.cloudflare-dns.com    (malware blocking)
  - https://1.1.1.2/dns-query             (malware blocking)
  - https://8.8.8.8/dns-query             (Google, reliable)

FILTER LISTS:
  1.  AdGuard DNS filter
  2.  AdAway Default Blocklist
  3.  Steven Black hosts (ads+malware+fakenews+gambling+porn)
  4.  OISD Blocklist Full
  5.  Phishing Army Extended
  6.  NoCoin Filter List (cryptomining)
  7.  Dan Pollock's hosts
  8.  Hagezi Threat Intelligence Feeds (608K rules)
  9.  Hagezi Multi PRO++ (219K rules)
  10. URLhaus Malicious URL Blocklist
  11. Scam Blocklist by DurableNapkin
  12. ThreatFox IOCs
  13. Hagezi DNS-over-HTTPS/TLS Bypass
  14. Phishing URL Blocklist (PhishTank)

===============================================================================
