# Geographic & Jurisdiction-Specific OPSEC

## Overview

Operational security requirements vary **dramatically** by geography due to:
- National surveillance capabilities (Five Eyes vs. Non-Aligned)
- Legal frameworks (data retention laws, encryption backdoors)
- Adversary proximity (border crossings, extradition treaties)
- Infrastructure control (state-owned ISPs, Great Firewall)
- Hardware supply chain (camera-less devices, modified components)

**This layer covers country-specific threat models with extreme technical detail.**

---

## I. Five Eyes Alliance (Tier 3.5 Surveillance)

### Countries: USA, UK, Canada, Australia, New Zealand

**Threat Model:** Mass surveillance, SIGINT dragnet, legal compulsion (NSA PRISM, GCHQ Tempora, UKUSA Agreement)

### 1.1 United States

**Surveillance Infrastructure:**
- **NSA XKEYSCORE:** Full-take internet surveillance (300+ servers worldwide)
- **PRISM:** Direct access to Google, Apple, Microsoft, Facebook servers
- **Section 702 FISA:** Warrantless surveillance of non-US persons
- **Upstream Collection:** Backbone fiber taps (AT&T Room 641A)
- **CALEA:** Mandatory ISP backdoors for law enforcement

**Legal Framework:**
```
Patriot Act (2001): Expanded surveillance powers
CLOUD Act (2018): Extraterritorial data access
FISA 702: Non-US persons = no warrant required
National Security Letters (NSL): Gag orders on companies
Executive Order 12333: Foreign intelligence collection (no judicial oversight)
```

**Data Retention:**
- ISPs: No mandatory retention (varies by provider)
- Email: Stored indefinitely (third-party doctrine)
- VPN logs: No federal requirement, but NSL-compellable

**OPSEC Recommendations:**
```
DO:
- Assume all US-based services compromised (PRISM)
- Use non-US VPN providers (avoid jurisdiction)
- Encrypt before cloud upload (client-side E2EE)
- Tor + obfs4 bridges (bypass DPI)

DON'T:
- Trust US "warrant canary" (NSL gag orders unenforceable)
- Use ISP DNS (logged, shared with NSA)
- Cross US borders with unencrypted devices
```

**Hardware Considerations:**
- **Border Search Exception:** DHS can seize devices without warrant
- **Camera-less iPhone:** Not available (Apple US compliance)
- **Recommendation:** Burner device for border crossings, wipe before entry

**Attribution Weight (US Operations):**
- **V** = 0.95 (NSA full-take surveillance)
- **R** = 1.0 (Permanent retention via XKEYSCORE)
- **C** = 0.95 (Cross-INT fusion, PRISM)
- **AW** = 0.90 (CRITICAL)

---

### 1.2 China (Great Firewall + Social Credit)

**Threat Model:** State-controlled internet, real-name registration, AI-powered mass surveillance

**Surveillance Infrastructure:**
- **Great Firewall (GFW):** Deep Packet Inspection, protocol fingerprinting
- **Golden Shield:** Nationwide CCTV + facial recognition (600M cameras)
- **Social Credit System:** Behavioral scoring linked to internet activity
- **Real-Name Registration:** All SIMs, social media, internet cafes
- **MSS (Ministry of State Security):** Domestic intelligence, cyber operations

**Legal Framework:**
```
Cybersecurity Law (2017): Data localization, backdoor requirements
National Intelligence Law (2017): Compelled cooperation with intelligence
Data Security Law (2021): Cross-border data transfer restrictions
Personal Information Protection Law (2021): GDPR-like, but state-controlled
```

**Technical Restrictions:**
```
Banned Services:
- Google, Facebook, Twitter, YouTube
- WhatsApp (end-to-end encryption)
- Tor (actively blocked via DPI)
- VPNs (unauthorized providers blocked)

Approved Alternatives:
- WeChat (government backdoor confirmed)
- Baidu (censored search)
- Weibo (real-name, monitored)
```

**OPSEC Recommendations:**
```
DO:
- Use Shadowsocks obfuscated proxies (harder to detect than VPN)
- Domain fronting via CDNs (Cloudflare, Fastly)
- Tor + meek pluggable transport (looks like HTTPS)
- V2Ray + WebSocket + TLS (protocol mimicry)

DON'T:
- Use real identity for ANY service (social credit linkage)
- Trust local VPN providers (government-approved = compromised)
- Use WeChat for sensitive communications (plaintext to MSS)
- Assume private browsing is private (ISP logs mandatory)
```

**Hardware:**
- **Xiaomi, Huawei, ZTE:** Assumed backdoored (MSS access)
- **Camera-less Phone:** Not available (all devices registered)
- **Recommendation:** Non-Chinese hardware (iPhone, Pixel), factory reset before China entry

**GFW Bypass Techniques:**
```
Tier 1: V2Ray + VMess + WebSocket + TLS 1.3
Tier 2: Trojan (mimics HTTPS perfectly)
Tier 3: Custom protocol (requires coding)

Example V2Ray Config:
{
  "inbounds": [{
    "port": 10808,
    "protocol": "vmess",
    "settings": {
      "clients": [{"id": "UUID", "alterId": 64}]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {"path": "/ray"},
      "tlsSettings": {"serverName": "legitimate.domain.com"}
    }
  }]
}
```

**Attribution Weight (China Operations):**
- **V** = 1.0 (Total ISP control, real-name)
- **R** = 1.0 (Permanent social credit linkage)
- **C** = 1.0 (Facial recognition + behavioral scoring)
- **AW** = 1.0 (EXTREME - Assume full attribution)

---

### 1.3 Russia (SORM + VPN Bans)

**Threat Model:** FSB/GRU access, VPN blocking, encryption backdoors

**Surveillance Infrastructure:**
- **SORM (System for Operative Investigative Activities):** ISP-level wiretaps
- **Yarovaya Law (2016):** 6-month message/call retention by telecoms
- **RKN (Roskomnadzor):** Internet censorship, VPN blocking
- **FSB (Federal Security Service):** Domestic surveillance, SIGINT

**Legal Framework:**
```
Yarovaya Law: Mandatory 6-month metadata retention (messages, calls, locations)
VPN Ban (2017): VPNs must block banned sites or be blocked themselves
Encryption Backdoors: FSB can demand decryption keys
Anti-Anonymizer Law: Tor usage criminalized (rarely enforced)
```

**OPSEC Recommendations:**
```
DO:
- Use non-Russian VPNs (avoid Kaspersky VPN)
- Tor bridges (default Tor blocked)
- Encrypted messengers (Telegram is Russian, but E2EE)
- Avoid Yandex services (FSB access confirmed)

DON'T:
- Trust Russian telecom providers (SORM boxes mandatory)
- Use VK (Russian Facebook equivalent) for sensitive topics
- Assume Telegram is government-proof (founder exiled, but pressure remains)
```

**Hardware:**
- **Camera-less Phone:** Not commonly available
- **GLONASS Tracking:** Russian GPS alternative (assume tracked)
- **Recommendation:** Non-Russian devices, disable GLONASS

**Attribution Weight (Russia Operations):**
- **V** = 0.9 (SORM surveillance)
- **R** = 0.9 (Yarovaya 6-month retention)
- **C** = 0.8 (FSB cross-referencing)
- **AW** = 0.65 (HIGH)

---

## II. Privacy-Friendly Jurisdictions (Lower Surveillance)

### 2.1 Switzerland (Privacy Haven)

**Legal Framework:**
- **No EU GDPR:** Own data protection law (stricter in some ways)
- **No mandatory data retention:** ISPs not required to log
- **Strong attorney-client privilege:** Extends to tech companies

**OPSEC Benefits:**
```
ProtonMail: Swiss-based, E2EE email
ProtonVPN: No logs, Swiss jurisdiction
Threema: Secure messaging, Swiss servers
```

**Attribution Weight:** AW = 0.3 (LOW - strong legal protections)

---

### 2.2 Iceland (Journalist Protection)

**Legal Framework:**
- **Icelandic Modern Media Initiative (IMMI):** Whistleblower protection
- **No data retention:** ISPs don't log
- **WikiLeaks hosting history:** Strong free press protections

**OPSEC Benefits:**
```
1984 Hosting: Privacy-focused VPS
OrangeWebsite: Anonymous VPS payments
```

**Attribution Weight:** AW = 0.25 (LOW)

---

## III. Hardware-Specific OPSEC

### 3.1 Camera-Less Devices

**Threat Model:** Visual surveillance, facial recognition, EXIF GPS leaks

**Available Options:**

**1. BlackBerry Classic (2014)**
- Physical keyboard, no front camera
- Discontinued, but available used
- **Problem:** Outdated software (Android 4.4 equivalencies)

**2. Punkt MP02 (Minimal Phone)**
- 4G feature phone, no camera
- Swiss-made, privacy-focused
- **Limitation:** No smartphone apps

**3. Mudita Pure (E-ink Phone)**
- No camera, no apps, minimalist
- **Use Case:** Extreme OPSEC, burner device

**4. Modified iPhone (Camera Removal)**
```
Professional Camera Removal:
- Requires microsoldering skills
- Remove front + rear camera modules
- Fill holes with epoxy (tamper-evident)
- **Problem:** Voids warranty, may trigger security alerts
```

**Custom Hardware:**
```
Librem 5 (Purism):
- Hardware kill switches (camera, mic, WiFi, baseband)
- PureOS (Linux-based, open-source)
- **OPSEC Benefit:** Physical disconnect > software disable

PinePhone:
- Similar kill switches
- PostmarketOS support
- **Cost:** ~$200 USD
```

**OPSEC Analysis:**
```
Camera-less Phone:
- V = 0.0 (No visual data leakage)
- R = 0.0 (No EXIF to retain)
- C = 0.3 (Reduced cross-layer correlation)
- AW = 0.0 (ZERO visual attribution)

Standard Phone:
- V = 0.9 (EXIF GPS, facial recognition)
- R = 1.0 (Photos permanent)
- C = 0.9 (GEOINT + HUMINT fusion)
- AW = 0.81 (CRITICAL)
```

---

### 3.2 Hardware Kill Switches

**Purism Librem 5:**
```
Kill Switches:
1. Cameras (front + rear)
2. Microphone
3. WiFi/Bluetooth
4. Cellular baseband

OPSEC Benefit:
- Physical air-gap when needed
- No software-level compromise possible
```

**DIY Hardware Modifications:**
```
Microphone Disable:
- Desolder mic components
- Install physical switch in audio path
- **Risk:** May void warranty

Camera Disable:
- Remove camera modules
- Cover with opaque tape (low-tech but effective)
```

---

## IV. Border Crossing OPSEC

### 4.1 Device Seizure Protocols (By Country)

**United States (DHS):**
```
Legal Authority:
- Border Search Exception (no warrant needed)
- CBP can demand passwords
- Refusal = detention + device seizure

OPSEC Protocol:
1. Travel with wiped burner device
2. Cloud-sync actual data (access after border)
3. Use temporary email (delete after entry)
4. Plausible deniability: Looks like vacation phone
```

**China:**
```
Entry Requirements:
- Install government surveillance app (mandatory for Xinjiang)
- Phone inspection at border (manual + automated)
- Social media history checked

OPSEC Protocol:
1. Factory reset before entry
2. No VPN apps installed
3. Sanitized social media (delete anti-China posts in advance)
4. Burner WeChat account (real-name verified, but generic)
```

**Russia:**
```
FSB Border Controls:
- Random device searches
- SIM registration required
- Encrypted devices = suspicion

OPSEC Protocol:
1. No Tor/VPN apps visible
2. Use within Russia only
3. Burn after exit
```

---

## V. Comparison Matrix

| Country | Surveillance | Data Retention | VPN Legal | Tor Legal | AW Score |
|---------|-------------|----------------|-----------|-----------|----------|
| **USA** | NSA XKEYSCORE | Varies | ✅ Yes | ✅ Yes | 0.90 |
| **UK** | GCHQ Tempora | 12 months | ✅ Yes | ✅ Yes | 0.88 |
| **China** | GFW + Social Credit | Permanent | ❌ Banned | ❌ Blocked | 1.00 |
| **Russia** | SORM | 6 months | ⚠️ Restricted | ⚠️ Restricted | 0.65 |
| **Germany** | BND | 10 weeks | ✅ Yes | ✅ Yes | 0.55 |
| **Switzerland** | Minimal | None | ✅ Yes | ✅ Yes | 0.30 |
| **Iceland** | Minimal | None | ✅ Yes | ✅ Yes | 0.25 |

---

## VI. Recommendations by Threat Tier

### Tier 1 (Consumer Privacy)
- **Location:** Any country
- **Hardware:** Standard smartphone
- **OPSEC:** VPN, encrypted messengers

### Tier 2 (Journalist/Activist)
- **Location:** Avoid China, Russia
- **Hardware:** Librem 5 (kill switches)
- **OPSEC:** Tor, vetted VPN, E2EE

### Tier 3 (High-Risk Operations)
- **Location:** Privacy havens (Switzerland, Iceland)
- **Hardware:** Camera-less + burner devices
- **OPSEC:** Air-gap, multi-hop VPN, Tor bridges

### Tier 3.5 (Nation-State Evasion)
- **Location:** Non-extradition countries
- **Hardware:** Modified devices, hardware kill switches
- **OPSEC:** Assume all communications monitored, plausible deniability mandatory

---

## VII. Technical Deep Dives

### 7.1 Great Firewall Evasion (Advanced)

**V2Ray Configuration (WebSocket + TLS):**
```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 1080,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "your.server.com",
        "port": 443,
        "users": [{
          "id": "YOUR-UUID",
          "alterId": 64,
          "security": "auto"
        }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {"path": "/v2ray"},
      "tlsSettings": {
        "serverName": "your.server.com",
        "allowInsecure": false
      }
    }
  }]
}
```

**Why This Works:**
- **WebSocket:** Looks like normal HTTPS traffic
- **TLS 1.3:** Encrypted SNI (hides destination)
- **Domain Fronting:** CDN hides actual server
- **Pluggable Transports:** Can mimic any protocol

---

### 7.2 Camera-less iPhone Mod (DIY)

**Tools Required:**
- Pentalobe screwdriver (P2)
- Tri-point screwdriver
- Suction cup
- Spudger
- Tweezers
- Soldering iron (for advanced mods)

**Procedure:**
```
1. Power off iPhone
2. Remove pentalobe screws (bottom)
3. Lift display with suction cup
4. Disconnect battery
5. Remove front camera assembly
6. Disconnect rear camera flex cable
7. Remove rear camera module
8. Fill camera holes with black epoxy
9. Reassemble

Warning: Voids warranty, may trigger Face ID errors (front camera needed)
```

**Alternative:** Use Librem 5 with hardware kill switches (no modding)

---

## VIII. Country-Specific Operational Guidelines

### USA Operations:
```
✅ DO:
- Use non-US email/VPN
- Encrypt before cloud storage
- Tor for anonymity
- Border device wipe

❌ DON'T:
- Trust US cloud providers (PRISM)
- Use SMS 2FA (SS7 vulnerable)
- Cross border with sensitive data
```

### China Operations:
```
✅ DO:
- V2Ray/Trojan for GFW bypass
- Burner WeChat (real-name required)
- Non-Chinese hardware
- Sanitize social media in advance

❌ DON'T:
- Use real identity
- Trust local VPNs
- Assume encryption works (state backdoors)
```

### Russia Operations:
```
✅ DO:
- Non-Russian VPN
- Tor bridges
- Avoid Yandex services

❌ DON'T:
- Trust Russian telecoms (SORM)
- Use VK for sensitive topics
```

---

## IX. References

### Academic:
- "The Great Firewall of China" (Xu et al., 2011)
- "Five Eyes Intelligence Alliance" (Leigh & Harding, 2013)
- "SORM and Russian Internet Surveillance" (Soldatov & Borogan, 2015)

### Legal:
- USA PATRIOT Act (2001)
- China Cybersecurity Law (2017)
- Russia Yarovaya Law (2016)
- GDPR (EU 2018)

### Technical:
- V2Ray Protocol Specification
- Tor Pluggable Transports
- Domain Fronting Techniques

---

**Related:**
- [[APT Operations & SOC Evasion]] - Advanced tradecraft
- [[Infrastructure Stealth]] - Server-side geographic considerations
- [[Personal OPSEC Checklist]] - Hardware recommendations

---

*知己知彼，百战不殆*

"Geography is destiny. Jurisdiction determines surveillance. Choose wisely."

**OPSEC is jurisdiction-dependent. Threat model accordingly.**
