# India - Surveillance & OPSEC

## Threat Classification: **TIER 2** (Moderate Surveillance)

**Adversaries:**
- Intelligence Bureau (IB) - Domestic intelligence
- Research and Analysis Wing (RAW) - Foreign intelligence
- Central Monitoring System (CMS) - Telecom intercept
- State police cyber cells

---

## I. Legal Framework

### 1.1 Surveillance Laws

**Information Technology Act 2000 (Amended 2008):**
```
Section 69: Government can intercept, decrypt any electronic communication
Section 69B: Mandatory blocking of websites (no judicial oversight)
Section 66A (struck down 2015): Criminalized "offensive" speech
```

**Telegraph Act 1885:**
- Allows government to intercept phone calls
- No warrant required for "national security"

**Central Monitoring System (CMS):**
- Direct access to telecom infrastructure
- Real-time call monitoring, SMS intercept
- No ISP involvement needed (bypasses intermediaries)

**Data Retention:**
- Telecom: Call records (3 years), tower location (1 year)
- ISPs: No mandatory retention, but can be compelled
- Email: Indefinite (third-party doctrine)

---

## II. Surveillance Infrastructure

### 2.1 NATGRID (National Intelligence Grid)

**Capability:** Centralized database integrating 21+ databases:
```
Data Sources:
- Immigration records
- Banking transactions (> ₹50,000)
- Train/flight bookings
- Phone call records (CMS)
- Income tax filings
- Passport applications
- Vehicle registration
```

**OPSEC Implication:**
- Cross-database correlation
- Pattern analysis (travel + banking + telecom)
- Attribution Weight: 0.75 (HIGH)

---

### 2.2 Central Monitoring System (CMS)

**Technical Details:**
```
Deployed: 2013-2014
Coverage: All telecom operators (Airtel, Jio, Vodafone-Idea)
Capability:
- Real-time call intercept (no operator involvement)
- SMS content monitoring
- Tower location tracking
- IMEI/IMSI logging
```

**Lawful Intercept Orders:**
- Issued by Home Secretary (no judicial oversight)
- Telecom operators must comply within 4 hours
- ~9,000-15,000 intercept orders annually (estimated)

**Attribution Weight:** AW = 0.85 (CRITICAL)

---

### 2.3 Aadhaar (Biometric ID System)

**Coverage:** 1.3+ billion residents

**Data Collected:**
- Fingerprints (10 fingers)
- Iris scans (both eyes)
- Facial photograph
- Linked to: Bank accounts, SIM cards, tax filings

**OPSEC Threat:**
```
Biometric Linkage:
- SIM card requires Aadhaar (2017 mandate, later relaxed)
- Bank account opening needs Aadhaar
- Cross-database correlation via Aadhaar UID

Risk: Single identifier links all activities
Attribution Weight: 0.90 (CRITICAL)
```

**Mitigations:**
- Use pre-2017 SIM cards (no Aadhaar linkage)
- Burner SIMs purchased from grey market (unregistered)
- Avoid Aadhaar-linked services

---

## III. Internet Surveillance & Censorship

### 3.1 Internet Shutdowns

**Frequency:** World leader in internet shutdowns

**Statistics (2020-2023):**
- 500+ shutdowns (Kashmir, farmer protests, riots)
- Duration: Hours to 18+ months (Kashmir 2019-2020)

**Mechanism:**
- Section 144 CrPC (public order)
- Telecom operators ordered to disable mobile data, broadband

**OPSEC Implication:**
- Unreliable connectivity during civil unrest
- Satellite internet (Starlink) not yet available in India

---

### 3.2 Website Blocking

**Legal Basis:** IT Act Section 69A

**Blocked Services:**
- ProtonMail (intermittent blocks)
- Telegram (temporary bans during protests)
- VPN websites (ExpressVPN, NordVPN domains blocked)

**Current Status (2026):**
- No Great Firewall-level DPI
- DNS-based blocking (easy to bypass)

**Bypass Methods:**
```bash
# Change DNS to Cloudflare
1.1.1.1 / 1.0.0.1

# Or Google DNS
8.8.8.8 / 8.8.4.4

# VPN (Tor works but slow)
sudo apt install tor
systemctl start tor
# Configure browser to use SOCKS5 localhost:9050
```

---

## IV. Telecommunications OPSEC

### 4.1 SIM Card Registration

**Requirements (2023):**
- Government ID (Aadhaar preferred)
- Biometric verification (fingerprint, photo)
- Address proof

**Grey Market SIMs:**
- Unregistered SIMs available (₹100-500)
- Risk: Illegal, but enforcement low
- Use case: Burner operations

**Postpaid vs Prepaid:**
```
Prepaid:
- Less verification
- Cash payment possible
- Easy to discard

Postpaid:
- Strict verification (address proof required)
- Credit check
- Bill trail (avoid)
```

---

### 4.2 IMEI Tracking

**Mechanism:**
- All phones have unique IMEI (International Mobile Equipment Identity)
- Logged at every tower connection
- Cross-referenced with SIM IMSI (subscriber identity)

**OPSEC:**
```
Problem: IMEI + IMSI correlation
- Even if you change SIM, IMEI persists
- Authorities can track device movement

Solution:
- Use different device per operation
- Burner phone + burner SIM
- Never reuse IMEI across operations
```

---

## V. Financial Surveillance

### 5.1 Cash Transaction Limits

**Legal Restrictions:**
- Cash transactions > ₹2 lakh (₹200,000 / ~$2,400) prohibited (Section 269ST)
- Violators: 100% penalty

**OPSEC:**
- Split large payments (< ₹2L per transaction)
- Use hawala (informal money transfer) - RISK: Illegal
- Cryptocurrency (see below)

---

### 5.2 Banking Surveillance

**Know Your Customer (KYC):**
- Aadhaar-based e-KYC (biometric verification)
- All bank accounts linked to PAN (Permanent Account Number - tax ID)
- Transactions > ₹10 lakh flagged for tax scrutiny

**International Transfers:**
- SWIFT monitored by Financial Intelligence Unit (FIU)
- Crypto purchases via bank flagged

**OPSEC:**
```
DO:
- Multiple bank accounts (compartmentalize)
- Cash withdrawals (avoid ATM patterns)
- Peer-to-peer crypto (avoid exchanges)

DON'T:
- Single bank for all activity (correlation)
- Large unexplained deposits (tax notice)
```

---

## VI. Physical Surveillance

### 6.1 CCTV Coverage

**Urban Areas:**
- Delhi: 150,000+ CCTV cameras
- Mumbai: 5,000+ (expanding)
- Bangalore: Smart city CCTV networks

**Facial Recognition:**
- Deployed in Delhi (2020)
- Crime and Criminal Tracking Network and Systems (CCTNS)
- Accuracy: Moderate (challenges with diverse population)

**OPSEC:**
- Avoid prolonged CCTV gaze
- Cap + sunglasses (partial obscuration)
- Note: Full face covering illegal in some states

---

## VII. Border Crossing OPSEC

### 7.1 Land Borders

**High-Security Borders:**
- Pakistan (Line of Control - militarized)
- Bangladesh (fenced, patrolled)
- Myanmar (porous in northeast)

**Nepal/Bhutan:**
- Open border (no passport for Indians/Nepalis)
- Entry/exit not logged systematically
- OPSEC: Can cross without electronic trail

**Border Surveillance:**
- Biometric collection at airports
- No biometric at Nepal land crossings

---

### 7.2 Airport Security

**Entry/Exit System (EES):**
- Biometric (fingerprint + photo) at immigration
- Linked to Aadhaar database
- Foreign travel logged

**Device Search:**
- Random checks by customs
- No legal right to refuse (Customs Act)
- OPSEC: Sanitize devices before entry

---

## VIII. Cryptocurrency & Financial Privacy

### 8.1 Legal Status

**Current (2026):**
- Not banned, but heavily taxed
- 30% tax on crypto gains (2022 Budget)
- 1% TDS (Tax Deducted at Source) on all crypto transactions

**Exchanges:**
- WazirX, CoinDCX (KYC required)
- All transactions reported to tax authorities

**OPSEC:**
```
DO:
- P2P trading (LocalBitcoins, Bisq)
- Monero (privacy coin)
- Non-KYC exchanges (international)

DON'T:
- Buy via Indian exchange (tax trail)
- Large bank-to-crypto transfers (flagged)
```

---

## IX. Operational Recommendations

### 9.1 High-Risk Operations in India

**DO:**
```
1. Telecom:
   - Use grey market SIMs (unregistered)
   - Rotate SIMs weekly
   - Remove battery when not in use

2. Internet:
   - VPN always (no local IP)
   - Tor for high-risk activity
   - Change DNS (avoid ISP DNS)

3. Finance:
   - Cash for operational expenses
   - Crypto via P2P (no exchange)
   - Keep transactions < ₹2L

4. Physical:
   - Nepal border exit (no electronic log)
   - Avoid Aadhaar-linked services
   - CCTV awareness in urban areas

5. Travel:
   - Book transport via cash (avoid online)
   - Use agents for flight/train tickets (no direct ID)
   - Avoid loyalty programs
```

**DON'T:**
```
1. Never link Aadhaar to operational SIMs/banks
2. Don't use same IMEI across operations
3. Avoid smart city areas (heavy CCTV)
4. Don't discuss sensitive topics on unencrypted calls
5. Never assume privacy in hotel rooms
```

---

### 9.2 Journalist/Activist OPSEC

**Specific Threats:**
- IT Act Section 66A arrests (though struck down, still misused)
- UAPA (Unlawful Activities Prevention Act) - terrorism charges for dissent
- Pegasus spyware targeting (2021 revelations)

**Mitigations:**
```
Device Security:
- GrapheneOS (degoogled Android)
- Regular factory resets
- No iCloud/Google backup (data accessible to authorities)

Communications:
- Signal with disappearing messages
- Verify safety numbers (MITM protection)
- In-person meetings for critical info

Legal:
- Know your rights (IT Act, UAPA)
- Lawyer on retainer
- Emergency contact protocol
```

---

## X. Attribution Weight Summary

| Vector | AW Score | Notes |
|--------|----------|-------|
| CMS (Call Intercept) | 0.85 | Real-time monitoring |
| Aadhaar Biometric | 0.90 | Cross-database linkage |
| NATGRID Correlation | 0.75 | 21+ databases integrated |
| SIM Registration | 0.70 | Mandatory KYC |
| Banking KYC | 0.80 | PAN + Aadhaar linked |
| CCTV Facial Recognition | 0.60 | Moderate accuracy |
| Internet Monitoring | 0.50 | No DPI, DNS-level only |

**Overall India OPSEC Score: 0.73 (HIGH)**

---

## XI. References

### Legal:
- Information Technology Act 2000
- Telegraph Act 1885
- Justice K.S. Puttaswamy (Privacy) Judgment (2017)

### Reports:
- Amnesty International: "Targeted - NSO Group's Pegasus in India" (2021)
- Freedom House: "Freedom on the Net - India" (2023)
- Software Freedom Law Centre: "CMS Technical Report"

### News:
- The Wire: Ongoing OPSEC coverage
- MediaNama: Telecom surveillance reporting

---

**Related:**
- [[Geographic OPSEC]] - Overall framework
- [[Operational Tradecraft]] - Physical security
- [[APT Operations]] - Advanced techniques

---

*सत्यमेव जयते* (Truth Alone Triumphs)

"India: Democracy with surveillance. Know the laws. Use the borders."

**OPSEC in India = Aadhaar compartmentalization + Nepal border + grey market SIMs**
