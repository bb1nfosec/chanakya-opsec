# GCC Countries - Surveillance & OPSEC

## Overview

Gulf Cooperation Council (GCC): Saudi Arabia, UAE, Qatar, Kuwait, Bahrain, Oman

**Threat Classification: TIER 2-3** (High Surveillance, Varies by Country)

**Common Characteristics:**
- Monarchy-based governance  
- Extensive surveillance infrastructure (imported from West/China)
- Strict content laws (blasphemy, criticism of government)
- Advanced cyber operations (NSO Group Pegasus users)

---

## I. UAE (United Arab Emirates)

### Threat Level: **TIER 3** (Advanced Surveillance)

**Surveillance Infrastructure:**
- DarkMatter (state-owned cyber firm)
- Project

 Raven (ex-NSA operatives, SIGINT collection)
- Falcon Eye (AI-powered CCTV, facial recognition)
- ToTok app (government spy tool, banned by Apple/Google)

**Legal Framework:**
```
Cybercrime Law (2012):
- VPN use: Illegal if used for crime (vague wording = broad interpretation)
- Encryption: Can be compelled to decrypt
- Online criticism of government: Criminal offense

Penalties:
- VPN for VoIP (Skype, WhatsApp calls): Fine + jail possible
- Defamation of ruler: Imprisonment
```

**OPSEC Recommendations:**
```
DO:
- Use VPN (risk low if for privacy, not crime)
- Avoid criticizing government online (even encrypted)
- Burner devices for sensitive activity
- Satellite phone for critical comms (expensive, legal grey area)

DON'T:
- Use ToTok (government malware)
- Criticize UAE leadership (online or offline)
- Trust hotel WiFi (monitored)
- Assume Pegasus not deployed (UAE is NSO client)
```

**Attribution Weight:** AW = 0.88 (CRITICAL)

---

## II. Saudi Arabia

### Threat Level: **TIER 3** (Extensive Surveillance + HUMINT)

**Surveillance:**
- Citizen Lab: Pegasus spyware targeting dissidents
- Social media monitoring (Twitter, especially)
- CCTV in Mecca/Medina (facial recognition pilgrims)
- Telecom intercept (state-owned STC, Mobily, Zain)

**Legal:**
```
Anti-Cyber Crime Law:
- Production/transmission of material "impinging on public order, religious values" → imprisonment
- VPNs: Not explicitly illegal, widely used for Netflix
- Criticism of King/Islam: Severe penalties (death penalty possible)
```

**Specific Threats:**
```
- Jamal Khashoggi case (2018): Pegasus used to track, then murdered
- Cross-border reach: Saudi intelligence operates globally
- Female activists: Heavily targeted (Loujain al-Hathloul)
```

**OPSEC:**
```
DO:
- Assume all Saudi SIMs monitored
- Use international SIM (roaming, less surveillance)
- In-person communication only for critical matters
- Exit strategy (have funds abroad)

DON'T:
- Criticize government ANYWHERE (cross-border enforcement)
- Trust encrypted apps alone (Pegasus defeats Signal)
- Use Saudi-issued devices (potential backdoors)
```

**Attribution Weight:** AW = 0.92 (EXTREME)

---

## III. Qatar

### Threat Level: **TIER 2** (Moderate, but improving post-blockade)

**Notable:**
- Home to Al Jazeera (relatively freer press)
- Less surveillance than UAE/KSA (but still significant)
- Hosting FIFA 2022: Temporary surveillance expansion

**OPSEC:** Similar to UAE, but slightly lower risk

**Attribution Weight:** AW = 0.70

---

## General GCC OPSEC

**Border Crossings:**
```
- Biometric collection at airports (all GCC)
- Device searches uncommon but legal
- Sanitize before entry
```

**Cryptocurrency:**
```
- Legal in UAE (Dubai = crypto hub)
- Saudi: No official stance (grey area)
- Use: International exchanges (avoid local)
```

---

**Related:** [[Geographic OPSEC]], [[Pegasus Spyware Defense]]

*لا إله إلا الله* (There is no god but Allah)

"GCC: Surveillance as statecraft. Pegasus is presumed."
