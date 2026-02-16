# Secure DNS Server - სრული გზამკვლევი

## სერვერის მონაცემები

| პარამეტრი | მნიშვნელობა |
|---|---|
| **მოწყობილობა** | Raspberry Pi (aarch64) |
| **Hostname** | nullxxx |
| **Local IP** | 192.168.100.25 |
| **Tailscale IP** | 100.127.41.43 |
| **SSH პორტი** | 2222 |
| **SSH მომხმარებელი** | (your username) |
| **SSH პაროლი** | (set during setup) |
| **AdGuard პანელი** | http://192.168.100.25 |
| **AdGuard Username** | admin |
| **AdGuard Password** | (set during setup) |

---

## SSH შესვლა

```bash
ssh -p 2222 nullexxx@192.168.100.25
```

---

## AdGuard Home მართვა

### სერვისის კონტროლი
```bash
# სტატუსი
sudo systemctl status AdGuardHome

# რესტარტი
sudo systemctl restart AdGuardHome

# გაჩერება
sudo systemctl stop AdGuardHome

# ლოგები
sudo journalctl -u AdGuardHome -f
```

### კონფიგურაციის ფაილი
```
/opt/AdGuardHome/AdGuardHome.yaml
```

### ფილტრების განახლება (ხელით)
AdGuard პანელში: Filters → DNS Blocklists → Check for updates

### ფილტრების ავტო-განახლება
ყოველ **12 საათში** ავტომატურად ახლდება.

---

## Tailscale მართვა

```bash
# სტატუსი - ყველა მოწყობილობა
tailscale status

# IP ნახვა
tailscale ip -4

# ქსელის ტესტი
tailscale netcheck

# გათიშვა
sudo tailscale down

# ჩართვა
sudo tailscale up --accept-dns=false
```

### Tailscale Admin პანელი
https://login.tailscale.com/admin/dns

---

## Firewall (UFW)

```bash
# სტატუსი
sudo ufw status verbose

# ახალი პორტის გახსნა
sudo ufw allow <PORT>/tcp

# პორტის დახურვა
sudo ufw delete allow <PORT>/tcp

# გათიშვა (საგანგებო)
sudo ufw disable
```

### გახსნილი პორტები
| პორტი | სერვისი |
|---|---|
| 2222/tcp | SSH |
| 53/tcp+udp | DNS (AdGuard) |
| 80/tcp | AdGuard Web Panel |
| 41641/udp | Tailscale |

---

## Fail2Ban

```bash
# სტატუსი
sudo fail2ban-client status sshd

# დაბანილი IP-ების ნახვა
sudo fail2ban-client status sshd | grep "Banned"

# IP-ის განბანვა
sudo fail2ban-client set sshd unbanip <IP_ADDRESS>

# ლოგი
sudo tail -f /var/log/fail2ban.log
```

### კონფიგურაცია
- **Max attempts**: 3
- **Ban time**: 1 საათი
- **Find time**: 10 წუთი
- **Config**: `/etc/fail2ban/jail.local`

---

## ქსელის დიაგნოსტიკა

### DNS ტესტი
```bash
# AdGuard-ით resolution
dig @192.168.100.25 google.com +short

# ბლოკირების ტესტი (უნდა დააბრუნოს 0.0.0.0)
dig @192.168.100.25 ads.google.com +short

# ტელემეტრიის ბლოკირება
dig @192.168.100.25 telemetry.microsoft.com +short

# საშიში TLD ბლოკირება
dig @192.168.100.25 malware-test.tk +short

# DNS სიჩქარე
dig @192.168.100.25 github.com +stats | grep "Query time"
```

### ქსელის ტესტი Pi-დან
```bash
# ინტერნეტ კავშირი
ping -c 3 8.8.8.8

# DNS resolution
dig google.com +short

# Tailscale კავშირი
tailscale ping <DEVICE_IP>
```

---

## აქტიური ფილტრები (18 სია, 2,072,722 წესი)

### ძირითადი ფილტრები
| # | ფილტრი | წესები | რას ბლოკავს |
|---|---|---|---|
| 1 | AdGuard DNS filter | 148K | რეკლამები, ტრეკერები |
| 2 | AdAway Default | 6.5K | რეკლამები (მობილური) |
| 3 | Steven Black hosts | 163K | რეკლამა+malware+fakenews+gambling+porn |
| 4 | OISD Full | 206K | ყოვლისმომცველი ბლოკლისტი |
| 7 | Dan Pollock's hosts | 12K | რეკლამები, ტრეკერები |

### უსაფრთხოების ფილტრები
| # | ფილტრი | წესები | რას ბლოკავს |
|---|---|---|---|
| 5 | Phishing Army Extended | 155K | ფიშინგ საიტები |
| 8 | Hagezi Threat Intelligence | 608K | საფრთხეების დაზვერვა |
| 9 | Hagezi PRO++ | 219K | პროფესიონალური ბლოკირება |
| 10 | URLhaus | 582 | მავნე URL-ები |
| 12 | ThreatFox IOCs | 57K | მავნე ინდიკატორები (C2, botnet) |
| 14 | PhishTank | 24K | ფიშინგ URL-ები |
| 18 | RPiList Malware | 450K | მავნე პროგრამების დომენები |

### სპეციალიზებული ფილტრები
| # | ფილტრი | წესები | რას ბლოკავს |
|---|---|---|---|
| 6 | NoCoin Filter | 313 | კრიპტომაინინგ |
| 11 | Scam Blocklist | 2.5K | სკამ საიტები |
| 13 | Hagezi DoH/DoT Bypass | 3.5K | DNS bypass მცდელობები |
| 15 | Hagezi Badware Hoster | 1.3K | მავნე ჰოსტინგ პროვაიდერები |
| 16 | Hagezi Dynamic DNS | 1.5K | მავნე DynDNS დომენები |
| 17 | Hagezi DNS/VPN/Proxy Bypass | 14K | DNS bypass, უნებართვო VPN/Proxy |

---

## Custom Blocking Rules (55 წესი)

### ტელემეტრია
| რას ბლოკავს |
|---|
| `telemetry.*` - ყველა ტელემეტრიის დომენი |
| `metrics.*` - მეტრიკების შეგროვება |
| `analytics.*` - ანალიტიკა |
| `beacons.gvt2.com` - Google beacons |

### Windows ტელემეტრია
| რას ბლოკავს |
|---|
| `vortex.data.microsoft.com` |
| `settings-win.data.microsoft.com` |
| `watson.telemetry.microsoft.com` |
| `telemetry.microsoft.com` |

### Smart TV თვალთვალი
| რას ბლოკავს |
|---|
| `samsungacr.com` - Samsung ACR tracking |
| `lgtvsdp.com` - LG TV tracking |
| `smartclip.net` - Smart TV ads |

### IOT მოწყობილობების თვალთვალი
| რას ბლოკავს |
|---|
| `device-metrics-us.amazon.com` - Amazon/Alexa |
| `data.mistat.xiaomi.com` - Xiaomi |
| `tracking.miui.com` - MIUI tracking |

### საშიში TLD-ები (Top Level Domains)
| დაბლოკილი | მიზეზი |
|---|---|
| `.tk, .ml, .ga, .cf, .gq` | უფასო დომენები - 90%+ spam/malware |
| `.buzz, .surf, .rest, .quest` | სკამ/ფიშინგ დომენები |
| `.top, .xyz` | მაღალი რისკის TLD-ები |

### კრიპტო სკამები
| რას ბლოკავს |
|---|
| `*crypto-airdrop*` |
| `*free-bitcoin*` |
| `*claim-token*` |
| `*wallet-connect-app*` |
| `*metamask-update*` |

---

## დაცვის ფუნქციები

| ფუნქცია | სტატუსი | რას აკეთებს |
|---|---|---|
| **Safe Browsing** | ჩართული | Google Safe Browsing - ფიშინგ/malware გვერდების შემოწმება |
| **Safe Search** | ჩართული | Google, YouTube, Bing, DuckDuckGo, Yandex - უსაფრთხო ძებნა |
| **DNSSEC** | ჩართული | DNS პასუხების ავთენტიფიკაცია |
| **DNS-over-HTTPS** | ჩართული | დაშიფრული upstream DNS |
| **Parallel DNS** | ჩართული | ყველა upstream-ს ერთდროულად ეკითხება, სწრაფს იღებს |
| **Optimistic Cache** | ჩართული | ქეშიდან სწრაფი პასუხი, ფონზე განახლება |
| **DNS Cache** | 8MB | ხშირი მოთხოვნები ქეშიდან - სწრაფი პასუხი |
| **Cache TTL Min** | 300s | მინიმუმ 5 წუთი ქეშში - ნაკლები upstream მოთხოვნა |

---

## დაბლოკილი სერვისები

| სერვისი | მიზეზი |
|---|---|
| 9gag | არასასურველი კონტენტი |
| 4chan | არასასურველი კონტენტი |
| Tinder | არასასურველი სერვისი |

სერვისის განბლოკვა: AdGuard Panel → Blocked Services → მოხსენი ჩეკბოქსი

---

## Upstream DNS სერვერები (ყველა დაშიფრული DoH)

| სერვერი | დანიშნულება |
|---|---|
| dns10.quad9.net | Malware/phishing ბლოკირება DNS დონეზე |
| security.cloudflare-dns.com | Cloudflare security ფილტრი |
| 1.1.1.2 | Cloudflare malware blocking |
| 8.8.8.8 | Google DNS (საიმედო fallback) |

**Bootstrap DNS**: 9.9.9.9, 1.1.1.1, 8.8.8.8
**Fallback DNS**: Quad9 DoH, Cloudflare Security DoH, Google DoH

---

## სტატისტიკა და ლოგები

| პარამეტრი | მნიშვნელობა |
|---|---|
| **Query Log** | 7 დღე |
| **Statistics** | 7 დღე |
| **Filter auto-update** | ყოველ 12 საათში |

ნახვა: AdGuard Panel → Query Log / Dashboard

---

## Tailscale მოწყობილობები

| IP | სახელი | ტიპი |
|---|---|---|
| 100.127.41.43 | nullxxx (Pi) | Linux DNS Server |
| 100.80.119.55 | google-pixel-6-pro | Android |
| 100.93.209.11 | kali | Android |
| 100.82.144.71 | debian | Linux |
| 100.112.11.11 | null3xxx | Linux |

---

## ახალი მოწყობილობის დამატება

### სახლის WiFi-ზე
არაფერი არ სჭირდება - როუტერის DHCP ავტომატურად მიუთითებს AdGuard-ს.

### გარეთ (მობილურით)
1. ტელეფონზე დააინსტალირე Tailscale
2. შედი იგივე ანგარიშით (null3xxx@)
3. Tailscale ჩართე - DNS ავტომატურად AdGuard-ზე გავა

---

## Pi სერვერის უსაფრთხოება

### SSH Hardening
| პარამეტრი | მნიშვნელობა |
|---|---|
| **პორტი** | 2222 (არასტანდარტული) |
| **Root login** | აკრძალული |
| **Max attempts** | 3 |
| **Login grace time** | 30 წამი |
| **X11 Forwarding** | გამორთული |
| **Allowed users** | მხოლოდ nullexxx |

### Fail2Ban
| პარამეტრი | მნიშვნელობა |
|---|---|
| **Max attempts** | 3 |
| **Ban time** | 1 საათი |
| **Find time** | 10 წუთი |
| **Config** | `/etc/fail2ban/jail.local` |

### UFW Firewall
| პორტი | სერვისი |
|---|---|
| 2222/tcp | SSH |
| 53/tcp+udp | DNS (AdGuard) |
| 80/tcp | AdGuard Web Panel |
| 41641/udp | Tailscale |

ყველა სხვა incoming port **დაბლოკილია**.

### Kernel Hardening (`/etc/sysctl.d/99-security.conf`)
- ICMP redirects - გამორთული
- Source routing - გამორთული
- SYN cookies - ჩართული (DDoS დაცვა)
- ICMP broadcast - იგნორირება
- Martian packets - ლოგირება
- TCP hardening - SYN flood დაცვა

### Auto-updates
უსაფრთხოების განახლებები ავტომატურად ინსტალირდება.

### გათიშული არასაჭირო სერვისები
lightdm (GUI), cups (printer), bluetooth, ModemManager, PostgreSQL, rpcbind/NFS, avahi-daemon, wayvnc, cloud-init

---

## საგანგებო სიტუაციები

### Pi-ს SSH არ მუშაობს
1. SD ბარათი ამოიღე, კომპიუტერში ჩადე
2. შეასწორე: `rootfs/etc/ssh/sshd_config.d/hardening.conf`
3. ან UFW გათიშე: `rootfs/etc/ufw/ufw.conf`-ში `ENABLED=yes` → `ENABLED=no`
4. SD ბარათი ისევ Pi-ში ჩადე და ჩართე

### ინტერნეტი არ მუშაობს (DNS პრობლემა)
```bash
# კომპიუტერზე დროებით DNS შეცვლა
nmcli connection modify "Wired connection 1" ipv4.dns "1.1.1.1 8.8.8.8"
nmcli connection up "Wired connection 1"

# Pi-ს DNS-ზე დაბრუნება
nmcli connection modify "Wired connection 1" ipv4.dns "192.168.100.25"
nmcli connection up "Wired connection 1"
```

### AdGuard არ ჩაირთვება
```bash
sudo /opt/AdGuardHome/AdGuardHome --check-config
sudo journalctl -u AdGuardHome --no-pager -n 50
```

### Pi-ს IP შეიცვალა
არ უნდა შეიცვალოს (static IP), მაგრამ თუ მოხდა:
```bash
nmcli connection modify 'network' ipv4.method manual ipv4.addresses 192.168.100.25/24 ipv4.gateway 192.168.100.1
nmcli connection up 'network'
```

### Fail2Ban-მა შენი IP დაბანა
```bash
# სხვა მოწყობილობიდან შედი Pi-ზე და:
sudo fail2ban-client set sshd unbanip <SHENI_IP>
```

### საიტი შეცდომით დაიბლოკა
1. AdGuard Panel → Query Log → იპოვე დაბლოკილი domain
2. ღილაკზე "Unblock" დააჭირე
3. ან ხელით: Filters → Custom filtering rules → დაამატე: `@@||example.com^`

---

## ავტომატური ინსტალერი (ახალი Pi-სთვის)

```bash
git clone https://github.com/1truesystems/secure-dns-server.git
cd secure-dns-server
sudo ./secure-dns-setup.sh
```

GitHub: https://github.com/1truesystems/secure-dns-server

---

## სრული დაცვის მიმოხილვა

| ფენა | კომპონენტი | რას აკეთებს |
|---|---|---|
| **DNS Filtering** | 18 ფილტრი (2M+ წესი) | რეკლამები, malware, phishing, scams, trackers |
| **Custom Rules** | 55 წესი | ტელემეტრია, Smart TV, IOT, საშიში TLD, კრიპტო სკამი |
| **Safe Browsing** | Google Safe Browsing | ფიშინგ/malware გვერდების რეალურ-დროში შემოწმება |
| **Safe Search** | ყველა ძებნის სისტემა | უსაფრთხო ძებნის იძულება |
| **DNSSEC** | DNS validation | DNS spoofing-ის დაცვა |
| **DNS-over-HTTPS** | დაშიფრული upstream | ISP ვერ ხედავს DNS მოთხოვნებს |
| **Upstream Security** | Quad9 + Cloudflare Security | DNS დონეზე malware ბლოკირება |
| **Firewall** | UFW | მხოლოდ საჭირო პორტები |
| **SSH Hardening** | Port 2222 + Fail2Ban | Brute force დაცვა |
| **Kernel Hardening** | sysctl rules | DDoS, spoofing დაცვა |
| **Auto-updates** | unattended-upgrades | ავტომატური პატჩები |
| **VPN** | Tailscale | დაცვა გარეთაც (მობილურიდან) |
