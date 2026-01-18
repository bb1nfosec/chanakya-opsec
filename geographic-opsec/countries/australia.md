# Australia - Surveillance & OPSEC

## Threat Classification: **TIER 2-3** (Five Eyes Member, Advanced Surveillance, Anti-Encryption Laws)

**Key Factors:**
- Five Eyes intelligence alliance (with USA, UK, Canada, NZ)
- Telecommunications and Other Legislation Amendment (Assistance and Access) Act 2018 (**"Anti-Encryption Law"**)
- Australian Signals Directorate (ASD) - equivalent to NSA

---

## I. Legal Framework

### 1.1 Assistance and Access Act 2018

**Most Controversial Provisions:**

**Technical Assistance Notices (TAN):**
```
Government can compel companies to:
- Provide access to encrypted communications
- Install backdoors in software
- Hand over encryption keys (if feasible)

Gag orders:
- Companies cannot disclose TAN (criminal offense)
- No canary clauses allowed

Impact:
- Australian tech companies potentially compromised
- International trust degraded (can Australian software be trusted?)
```

**Technical Capability Notices (TCN):**
```
- Force companies to build capabilities to decrypt
- Can require systemic weaknesses (debated)
```

**OPSEC Implication:**
```
WARNING: Avoid Australian-based encrypted services
- ProtonMail (Swiss) > Australian email provider
- Signal (USA, but open-source + E2EE) > Australian messenger
- Assumption: Any Australian company may have government backdoor
```

---

### 1.2 Metadata Retention

**Telecommunications (Interception and Access) Amendment (Data Retention) Act 2015:**
```
ISPs/Telcos must retain metadata for 2 years:
- Phone call times, duration, parties (NOT content)
- SMS times, parties (NOT content)
- Internet connection times, upload/download volume
- IP addresses assigned
- Email metadata (NOT content)

Access:
- 80+ government agencies can access (no warrant)
- Police, tax office, even local councils (controversial)
```

**OPSEC Impact:**
```
Metadata reveals:
- Who you contact (social graph)
- When you communicate (behavioral patterns)  
- Where you are (IP geolocation, cell towers)

Mitigation:
- VPN (hides IP from ISP logs)
- Tor (anonymizes connections)
- Signal (encrypted metadata where possible)
```

**Attribution Weight:** AW = 0.85 (CRITICAL)

---

## II. Surveillance Infrastructure

### 2.1 Five Eyes Integration

**Australian Signals Directorate (ASD):**
- Works with NSA, GCHQ, CSEC (Canada), GCSB (New Zealand)
- Access to XKEYSCORE (NSA's database)
- Surveillance data shared across Five Eyes

**Pine Gap:**
- Joint USA-Australia SIGINT base (Northern Territory)
- Satellite intercept, global surveillance
- Part of ECHELON network

---

### 2.2 Biometric Entry/Exit

**SmartGates:**
- Automated border processing (facial recognition)
- Biometric data stored (passport photo, fingerprints)
- Linked to immigration database

**Australian Border Force (ABF):**
- Can search devices at border without warrant
- Refusal to provide password: Possible detention, device seizure
- OPSEC: Sanitize devices before entry

---

##III. Operational Recommendations

### 3.1 Communication

**DO:**
```
- Use non-Australian encrypted services (Signal, ProtonMail)
- VPN always (hide from metadata retention)
- Tor for high-risk activity
- Assume Five Eyes monitoring of international traffic
```

**DON'T:**
```
- Trust Australian messenger apps (TAN risk)
- Assume metadata privacy (2-year retention)
- Cross border with sensitive data unencrypted
```

---

### 3.2 Financial Privacy

**Cash Limit:**
- Cash transactions > AUD $10,000 require reporting (anti-money laundering)
- Banks must report suspicious activity (AUSTRAC - financial intelligence)

**Cryptocurrency:**
- Legal, but exchanges require KYC (Coinbase, Binance Australia)
- Capital gains tax applies
- Use: Privacy coins (Monero), P2P trading

---

### 3.3 Internet

**Censorship:**
- Minimal compared to China/Russia
- Some sites blocked (piracy, child abuse)
- ISP-level DNS/IP blocking (easy to bypass)

**VPN:**
- Legal, widely used
- No restrictions

---

## IV. Attribution Weight Summary

| Vector | AW Score | Notes |
|--------|----------|-------|
| Metadata Retention | 0.85 | 2 years, 80+ agencies |
| Five Eyes SIGINT | 0.90 | ASD + NSA cooperation |
| TAN Backdoors | 0.80 | Australian services compromised |
| Border Biometrics | 0.75 | Facial recognition, device search |
| Financial Surveillance | 0.70 | AUSTRAC monitoring |

**Overall Australia OPSEC Score: 0.80 (HIGH)**

---

**Related:** [[Five Eyes Alliance]], [[Anti-Encryption Laws]], [[Border OPSEC]]

*Fair dinkum* (Honest, genuine)

"Australia: Five Eyes partner. Metadata retained. Encryption backdoors legal. Act accordingly."
