# Darknet & Darkweb OPSEC

## Overview

The "dark web" (accessed via Tor, I2P, Freenet) offers **anonymity layers** absent from clearnet, but introduces **unique attribution risks** if used incorrectly.

**Threat Model:** Law enforcement honeypots, malware, scams, de-anonymization attacks

**This guide covers operational security for darknet access with extreme technical detail.**

---

## I. Tor (The Onion Router)

### 1.1 Tor Architecture

**How It Works:**
```
Client → Entry Node → Middle Node → Exit Node → Destination

Encryption Layers:
- Entry sees: Your IP, but not destination
- Middle sees: Nothing useful (relay only)
- Exit sees: Destination, but not your IP
- Destination sees: Exit IP (not yours)

Onion Services (.onion):
Client → Entry → Rendezvous Point → Service
- No exit node (end-to-end encryption)
- Service doesn't see your IP
```

**Attack Vectors:**
1. **Traffic Correlation:** NSA/GCHQ can correlate entry + exit if they control both
2. **Malicious Exit Nodes:** Can modify unencrypted HTTP traffic
3. **Browser Fingerprinting:** Tor Browser resists, but JS/plugins leak
4. **Timing Attacks:** Patterns in traffic timing can de-anonymize

---

### 1.2 Tor Setup (OPSEC-Hardened)

**Do NOT Use:**
- Regular browser with Tor proxy (leaks)
- Tor on Windows (too many leak vectors)
- VPN + Tor (debated, see below)

**Recommended Setup:**

**Option 1: Tails OS (Amnesic Live Boot)**
```
What: Debian-based OS that routes all traffic through Tor
Boot: From USB, leaves no trace on hard drive
Benefits:
- Amnesia (no persistence by default)
- Tor enforced at network level
- Pre-configured for security

Download:
https://tails.boum.org/

Verification:
- Verify GPG signature (prevent MITM)
gpg --verify tails-amd64-5.x.img.sig tails-amd64-5.x.img

Boot:
1. Insert USB
2. Reboot computer
3. Select USB in BIOS boot menu
4. Tails loads (RAM only, no HDD writes)
```

**Option 2: Whonix (VM-based)**
```
Architecture:
- Gateway VM (routes all traffic through Tor)
- Workstation VM (isolated, can't leak IP)

Setup:
1. Download Whonix from whonix.org
2. Verify signatures
3. Import both VMs into VirtualBox/KVM
4. Start Gateway, then Workstation
5. All Workstation traffic → Tor (enforced at VM level)

Benefits:
- Even if Workstation compromised, IP doesn't leak
- Gateway enforces Tor (no bypass possible)
```

**Option 3: Qubes OS + Whonix**
```
Maximum security:
- Qubes: Security by compartmentalization
- Whonix: Tor enforcement
- Each activity in separate VM (disposable)

Use case: Nation-state threat model
```

---

### 1.3 Tor Browser OPSEC

**DO:**
```
1. Use Tor Browser (NOT Firefox + proxy)
   - Download: torproject.org
   - Built-in protections (NoScript, HTTPS Everywhere)

2. Security Level: Safest
   - Settings → Privacy & Security → Security Level: Safest
   - Disables JavaScript (prevents many attacks)

3. Never log in to personal accounts
   - Gmail, Facebook, Twitter → instant de-anonymization

4. Never download files and open while online
   - PDFs, Office docs can leak IP via embedded resources
   - Download → Disconnect → Open offline

5. Use .onion services when available
   - E.g., DuckDuckGo: 3g2upl4pq6kufc4m.onion
   - No exit node = more secure
```

**DON'T:**
```
1. Don't resize Tor Browser window
   - Fingerprinting via screen resolution

2. Don't install plugins (Flash, Java)
   - Massive leak vectors

3. Don't torrent over Tor
   - Leaks IP via DHT, UDP
   - Clogs network (bad etiquette)

4. Don't use Windows for high-risk
   - Too many OS-level leaks

5. Don't mix Tor + regular browsing in same session
   - Cross-contamination risk
```

---

### 1.4 VPN + Tor Debate

**Tor → VPN (Not Recommended):**
```
Flow: You → Tor → VPN → Internet

Problem:
- VPN sees your traffic (exit node knows identity)
- VPN knows you use Tor (metadata)
- No benefit over Tor alone
```

**VPN → Tor (Controversial):**
```
Flow: You → VPN → Tor → Internet

Pros:
- ISP doesn't know you use Tor
- Useful in countries that block Tor (China, Iran)

Cons:
- VPN sees you connect to Tor (metadata)
- If VPN logs, can correlate timing
- Adds trust in VPN provider

Verdict:
- Use only if ISP/country blocks Tor
- Use trusted VPN (Mullvad, IVPN - no logs)
```

---

### 1.5 Tor Bridges (Circumvent Blocking)

**Problem:** China, Iran block Tor entry nodes

**Solution:** Bridges (unlisted entry nodes)

**Setup:**
```
1. Get bridge addresses:
   - Email: bridges@torproject.org
   - Telegram: @GetBridgesBot
   - Web: https://bridges.torproject.org/

2. Types of bridges:
   a) obfs4 (most popular, looks like random traffic)
   b) meek (looks like Microsoft/Amazon traffic)
   c) Snowflake (WebRTC-based, very new)

3. Configure in Tor Browser:
   Settings → Tor → Bridges → Enter custom bridges

Example obfs4 bridge:
obfs4 192.0.2.1:1234 FINGERPRINT cert=CERTSTRING iat-mode=0
```

---

## II. Darknet Marketplaces OPSEC

### 2.1 Accessing Markets

**Threats:**
- Law enforcement honeypots (after seizure)
- Exit scams (marketplace suddenly closes, steals funds)
- Phishing sites (fake market URLs)
- Malware downloads

**Before Accessing:**
```
1. Use Tails/Whonix (never clearnet OS)

2. Verify .onion URL from multiple sources:
   - Darknet market subreddits (r/DarkNetMarkets - if exists)
   - DNM Bible (darknetlive.com)
   - PGP-signed messages from market admins

3. Enable JavaScript ONLY if needed (risky)

4. Never use real identity/email
   - Market accounts: random username
   - PGP key: generated fresh (no linkage to real identity)
```

---

### 2.2 Cryptocurrency OPSEC

**Never Use Bitcoin Directly:**
```
Problem: Bitcoin is pseudonymous, not anonymous
- All transactions public (blockchain)
- Chain analysis (Chainalysis, Elliptic)
- Exchanges KYC (link coins to identity)

If caught: "Follow the money" → your identity
```

**Recommended: Monero (XMR)**
```
Why:
- Ring signatures (sender ambiguity)
- Stealth addresses (recipient privacy)
- RingCT (amount hidden)

Result: Truly anonymous transactions

How to acquire:
1. Buy Bitcoin (KYC exchange if unavoidable)
2. Swap BTC → XMR via:
   - Bisq (decentralized exchange)
   - Cake Wallet (built-in exchange)
   - Trocador (Tor-accessible swapper)
3. Use XMR on darknet markets
```

**Bitcoin Mixing (Less Secure Alternative):**
```
Services: Wasabi Wallet (CoinJoin), Samourai Whirlpool

How it works:
- Mix your BTC with others
- Breaks transaction graph

Limitations:
- Not perfect anonymity
- Mixing services can be compromised
- Chainalysis can sometimes trace through mixes

Verdict: Use Monero if possible
```

---

### 2.3 PGP Encryption

**Why:** Encrypt addresses, messages on markets

**Setup:**
```bash
# Install GnuPG
sudo apt install gnupg

# Generate key pair
gpg --full-generate-key
# Select: RSA 4096-bit
# Name: Anonymous User (NOT real name)
# Email: anon@localhost (NOT real email)
# Passphrase: Strong (20+ chars)

# Export public key (share with vendors)
gpg --armor --export anon@localhost > pubkey.asc

# Encrypt message (vendor's public key)
echo "123 Main St, City, Country" | gpg --armor --encrypt --recipient vendor_key_id

# Decrypt (your private key)
gpg --decrypt encrypted_message.asc
```

**OPSEC:**
- Never link PGP key to real identity
- Generate new key per market
- Store private key on encrypted USB (not in cloud)

---

## III. I2P (Invisible Internet Project)

### 3.1 I2P vs Tor

**Differences:**
```
Tor:
- Designed for clearnet access via .onion
- Faster (optimized for low latency)
- Larger network

I2P:
- Designed for internal network (eepsites)
- Slower (optimized for anonymity, not speed)
- Smaller network, but harder to compromise

Use case:
- Tor: Accessing clearnet anonymously
- I2P: Hidden services (.i2p sites), file sharing
```

**Setup:**
```
1. Download I2P:
   https://geti2p.net/

2. Install:
   java -jar i2prouter-install.jar

3. Start:
   ./i2prouter start

4. Access console:
   http://127.0.0.1:7657

5. Configure browser proxy:
   HTTP Proxy: localhost:4444
   HTTPS Proxy: localhost:4445

6. Visit .i2p sites (eepsites)
```

---

## IV. Freenet

**Use Case:** Censorship-resistant publishing

**How It Works:**
- Distributed datastore (files split across nodes)
- No central servers
- Deniable storage (can't prove you host specific content)

**Access:**
```
Download: freenetproject.org
Use case: Anonymous forums, file hosting
Speed: Very slow (not for browsing)
```

---

## V. Darknet OPSEC Failures (Case Studies)

### 5.1 Silk Road (Ross Ulbricht)

**OPSEC Failures:**
1. **Early forum posts:** Used personal email (rossulbricht@gmail.com)
2. **Stack Overflow:** Asked "How to connect to Tor with PHP" using real name
3. **Fake ID package:** Intercepted at border (linked to residence)
4. **Laptop seizure:** Unencrypted, logged in as admin when arrested

**Lessons:**
- Never link real identity to darknet pseudonym
- Encrypt all devices (full disk encryption)
- Use burner emails for operational accounts

---

### 5.2 AlphaBay (Alexandre Cazes)

**OPSEC Failures:**
1. **Email in code:** Welcome emails sent from "pimp_alex_91@hotmail.com"
2. **Financial greed:** Cashed out to bank accounts in own name
3. **Laptop unencrypted:** Logged in when arrested (damning evidence)

**Lessons:**
- No real identity in any code/config
- Never cash out to personal bank
- Always encrypt devices (and log out!)

---

## VI. Operational Procedures

### 6.1 Creating Darknet Identity

**Compartmentalization:**
```
Never mix:
- Real identity → Darknet pseudonym
- Darknet accounts → Clearnet accounts
- Personal email → Operational email

Each operation = fresh identity:
- New username
- New PGP key
- New cryptocurrency wallet
- No reuse across marketplaces
```

**Operational Email:**
```
Use:
- ProtonMail (accessed via Tor)
- Tutanota (E2EE email)
- Cock.li (anonymous, Tor-friendly)

Never:
- Gmail, Yahoo (linked to phone, real identity)
```

---

### 6.2 Daily Darknet OPSEC Checklist

```
☐ Boot Tails/Whonix (not regular OS)
☐ Verify Tor circuit (check IP: check.torproject.org)
☐ Access .onion via bookmark (not search engine)
☐ Verify PGP signatures on messages
☐ Never download and open files while connected
☐ Clear clipboard before shutdown
☐ Tails: Shutdown (automatic wipe of RAM)
```

---

## VII. Advanced Techniques

### 7.1 Hidden Service Hosting

**Why:** Host anonymous website (.onion)

**Setup:**
```bash
# Edit torrc
sudo nano /etc/tor/torrc

# Add:
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:80

# Restart Tor
sudo systemctl restart tor

# Get .onion address
sudo cat /var/lib/tor/hidden_service/hostname
# → abc123xyz.onion
```

**OPSEC:**
- Host on dedicated server (not home)
- Use bulletproof hosting (offshore, no logs)
- Never link to real identity
- HTTPS even on .onion (defense in depth)

---

### 7.2 OpSec for Whistleblowers

**Scenario:** Leaking documents anonymously

**Protocol:**
```
1. Acquire documents:
   - Never from work computer (logged)
   - Use personal device (air-gapped if possible)
   - Metadata removal (see below)

2. Metadata sanitization:
   - EXIF from images: exiftool -all= file.jpg
   - Office docs: Open in LibreOffice, "Save As" (removes hidden data)
   - PDFs: Print to PDF (strips metadata)

3. Upload:
   - SecureDrop (Tor-based whistleblower platform)
     - Used by: NYT, Guardian, Washington Post
   - Never email directly

4. Cover:
   - File access: Can employer see who opened file?
   - Network logs: VPN/Tor to access docs
   - Timing: Don't leak immediately after learning info (correlation)
```

**SecureDrop Addresses:**
- The Guardian: theguardian.securedrop.tor.onion
- NYT: nytimes.securedrop.tor.onion
- Washington Post: washingtönpost.securedrop.tor.onion

---

## VIII. Detection & Countermeasures

### 8.1 Traffic Analysis Attacks

**Threat:** NSA/GCHQ can correlate Tor entry and exit

**How:**
```
1. Control entry node (sees your IP)
2. Control exit node (sees traffic pattern)
3. Correlate timing → de-anonymize

Disclosed: NSA "XKEYSCORE" program
- Monitored Tor users
- Flagged for further surveillance
```

**Mitigation:**
```
- Use .onion services (no exit node)
- Randomize traffic timing (hard for users)
- Guard nodes (Tor uses consistent entry for 3 months)
- Trust: Tor is still best available tool
```

---

### 8.2 Browser Fingerprinting

**Threat:** Canvas fingerprinting, WebGL, fonts

**Tor Browser Protections:**
```
- Uniform window size
- Disabled WebGL
- Limited fonts (prevents enumeration)
- NoScript (disables JS on Safest mode)

Still risky:
- JavaScript enabled = fingerprinting possible
- Use Safest mode for high-risk
```

---

## IX. Legal Considerations

### 9.1 Is Tor Legal?

**Most Countries:** YES
- USA: Legal (EFF-verified)
- EU: Legal
- Japan, South Korea: Legal

**Restricted:**
- China: Blocked (use bridges)
- Iran: Blocked (use bridges)
- Russia: Technically legal, but monitored

**Note:** Using Tor is legal, but **what you do** may not be.

---

## X. Recommended Resources

### Documentation:
- **Tor Project:** torproject.org
- **Tails OS:** tails.boum.org
- **Whonix:** whonix.org
- **EFF Surveillance Self-Defense:** ssd.eff.org

### Communities:
- **r/Tor** (Reddit)
- **r/onions** (Reddit - .onion links)
- **Dread** (Darknet Reddit alternative - .onion only)

### Tools:
- **Tor Browser:** torproject.org/download
- **Tails:** Amnesic OS
- **Whonix:** VM-based anonymity
- **OnionShare:** Share files via .onion

---

## XI. Threat Model Assessment

| Activity | Tool | AW Score | Notes |
|----------|------|----------|-------|
| Browsing clearnet | Tor Browser | 0.30 | Exit node sees traffic |
| .onion services | Tor Browser | 0.15 | No exit, end-to-end |
| Marketplace browsing | Tails + Tor | 0.20 | Amnesic OS |
| Bitcoin transactions | Bitcoin + Tor | 0.75 | Blockchain analysis |
| Monero transactions | Monero + Tor | 0.25 | True anonymity |
| Hidden service hosting | Tor + Offshore | 0.35 | Depends on opsec |

---

**Related:**
- [[Operational Tradecraft]] - Physical security
- [[APT Operations]] - Advanced techniques
- [[Geographic OPSEC]] - Country-specific threats

---

*"На войне как на войне"* (In war as in war)

"The dark web is a tool. OPSEC determines if it anonymizes or incriminates."

**Darknet OPSEC = Tails + .onion + Monero + PGP + Compartmentalization**
