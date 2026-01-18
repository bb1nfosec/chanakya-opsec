# Threat Model

## Adversary Classification

CHANAKYA models threats based on **capability tiers**, not intent. Understanding what adversaries *can* do is more valuable than guessing what they *will* do.

---

## Tier 0: Baseline Internet Observer

### Capabilities
- Can observe public-facing services (ports, protocols)
- Can perform basic OSINT (WHOIS, DNS lookups)
- Can use commodity scanning tools (nmap, masscan)

### Visibility
- **Network**: Public IP addresses only
- **DNS**: Queries to authoritative nameservers (if they control one)
- **Routing**: Public BGP announcements only
- **Metadata**: None beyond public timestamps

### OPSEC Implications
**CHANAKYA does not focus on this tier** — basic hygiene defeats Tier 0.

---

## Tier 1: Commercial Threat Intelligence

### Capabilities
- Access to commercial threat feeds (passive DNS, reputation databases)
- Netflow/sFlow data from ISP partnerships
- Automated correlation across multiple sources
- Historical data retention (months to years)
- Sinkhole infrastructure

### Visibility
- **Network**: Netflow metadata, AS-level visibility
- **DNS**: Passive DNS databases (commercial feeds like Farsight DNSDB, VirusTotal)
- **Routing**: BGP route monitoring (RouteViews, RIPE RIS)
- **Metadata**: Reputation tagging, first-seen/last-seen timestamps
- **Sinkholes**: Queries to known malicious domains trigger alerts

### Data Sources
- **Passive DNS**: Farsight DNSDB, VirusTotal, Cisco Umbrella
- **NetFlow**: ISP partnerships, IX peering visibility
- **BGP Monitoring**: RouteViews, RIPE RIS, RADB
- **Reputation Feeds**: Spamhaus, abuse.ch, AlienVault OTX
- **Threat Intelligence Platforms**: MISP, ThreatConnect, Anomali

### Detection Methods
1. **Sinkhole Alerting**: DNS queries to sinkholed C2 domains
2. **Passive DNS Correlation**: Historical domain-IP associations
3. **AS Reputation**: Traffic from known bulletproof hosting
4. **Behavioral Scoring**: Anomaly detection based on baselines

### OPSEC Requirements Against Tier 1
- Avoid sinkholed domains (DGA awareness, threat feed tracking)
- Minimize passive DNS footprint (ephemeral infrastructure)
- AS reputation hygiene (avoid known bad ASes)
- DNS resolver OpSec (no leakage to public resolvers)

**CHANAKYA defends against Tier 1+ adversaries.**

---

## Tier 2: Advanced Persistent Threat (APT)

### Capabilities
- All Tier 1 capabilities, plus:
- Custom infrastructure analysis (manual threat hunting)
- Long-term behavioral tracking (months to years)
- Cross-organization correlation (linking operations across targets)
- Bespoke detection signatures
- Adversary-specific TTPs database
- Code similarity analysis (malware/tooling attribution)

### Visibility
- **Network**: Deep packet inspection (DPI) at chokepoints, full session metadata
- **DNS**: Private recursive resolver logs (if they compromise infrastructure)
- **Routing**: BGP hijacking awareness, route leak monitoring
- **Userland**: Reverse-engineered tooling, binary similarity clustering
- **Metadata**: Multi-year operational tempo analysis, human pattern recognition

### Analyst Resources
- Dedicated threat hunting teams
- Custom analysis tools and frameworks
- Adversary-specific knowledge bases
- Cross-reference with other campaigns

### Detection Methods
1. **Behavioral Clustering**: Group operations by TTPs, infrastructure patterns
2. **Infrastructure Pivoting**: Link domains/IPs via shared characteristics (SSL certs, registrar patterns, hosting relationships)
3. **Code Similarity**: Match binaries to known toolsets via fuzzy hashing (ssdeep, ImpHash)
4. **Temporal Correlation**: Identify operational cadence across campaigns
5. **Targeted Collection**: Focus on specific adversaries with known TTPs

### OPSEC Requirements Against Tier 2
- Operational security across time (no reused infrastructure)
- Tooling diversity (avoid signature toolsets)
- Infrastructure compartmentalization (no cross-campaign linkage)
- Temporal obfuscation (randomized cadence, multi-timezone operations)
- Strong correlation resistance (minimize signal overlap)

**CHANAKYA is designed primarily for Tier 2 defense.**

---

## Tier 3: Nation-State SIGINT (Strategic Intelligence)

### Capabilities
- All Tier 2 capabilities, plus:
- **Backbone-level visibility**: Undersea cable taps, IX peering intercepts (e.g., NSA TURBULENCE, GCHQ Tempora)
- **Full-take packet capture**: Store-and-analyze at massive scale (Utah Data Center scale)
- **Recursive resolver monitoring**: Direct access to major DNS resolver logs (legal compulsion of Google, Cloudflare, ISPs)
- **BGP routing omniscience**: Global BGP route monitoring, route leak exploitation
- **Endpoint compromise**: CNE (Computer Network Exploitation) capabilities, zero-day stockpiles
- **Collaboration with infrastructure providers**: Legal/extralegal access to ISP, cloud, CDN data

### Visibility

| Layer | Tier 1 | Tier 2 | **Tier 3** |
|-------|--------|--------|-----------|
| **Network** | Netflow metadata | DPI at chokepoints | **Backbone intercepts, full-take capture** |
| **DNS** | Passive DNS (commercial) | Focused resolver logs | **Recursive resolver omniscience (8.8.8.8, 1.1.1.1)** |
| **Routing** | Public BGP feeds | Route leak monitoring | **Global BGP tap, route manipulation** |
| **Endpoint** | None | Samples from campaigns | **CNE implants, zero-days** |
| **Metadata** | Historical (commercial) | Multi-year tracking | **Decades of retained data, cross-database correlation** |

### Known Programs & Capabilities
- **PRISM (NSA)**: Direct access to tech company data
- **Upstream (NSA)**: Fiber-optic intercepts at AT&T, Verizon facilities
- **MUSCULAR (NSA/GCHQ)**: Google/Yahoo internal network intercepts
- **Tempora (GCHQ)**: Full-take buffer of transatlantic cables (3-day retention)
- **XKeyscore (NSA)**: Query interface for global intercept database
- **TURBULENCE (NSA)**: Active network exploitation and manipulation
- **Equation Group (NSA TAO)**: HDD firmware implants, BIOS persistence

### Detection Methods
1. **Global Correlation Engine**: Link signals across continents, organizations, years
2. **Passive Infrastructure Mapping**: Built from years of intercept data
3. **Behavioral Attribution**: Link operations to known entities via long-term patterns
4. **Cryptanalysis**: Exploit weak crypto, metadata analysis despite encryption
5. **Supply Chain Exploitation**: Compromise development/delivery infrastructure
6. **Active Probing**: Beacon injection, route manipulation, targeted CNE

### OPSEC Reality Against Tier 3

**Uncomfortable truth**: Perfect OPSEC against Tier 3 is likely impossible.

#### Why?
1. **Visibility**: They see Internet infrastructure components you cannot avoid (BGP, DNS root servers, major IXs)
2. **Retention**: Decades of data enable retroactive analysis
3. **Resources**: Unlimited budgets, legal compulsion, extralegal operations
4. **Time**: They can wait years to correlate operations

#### Realistic Goal
Not "invisibility" but **raising the cost of attribution**:
- Force manual analysis (avoid automated detection)
- Create plausible deniability (multiple attribution candidates)
- Limit confidence (keep below operational threshold for action)
- Compartmentalize operations (limit blast radius of attribution)

**CHANAKYA acknowledges Tier 3 exists but focuses on making attribution expensive, not impossible.**

---

## Tier 4: Hypothetical Advanced Adversaries

### Capabilities (Speculative)
- Quantum cryptanalysis (break current public-key crypto)
- AI-driven correlation at scale (autonomous pattern detection)
- Supply chain omniscience (compromise of chip fabrication, compiler toolchains)
- Side-channel analysis at distance (RF emissions, timing attacks via network)
- Unknown techniques beyond public knowledge

### OPSEC Against Tier 4
**Unknown.** CHANAKYA does not model adversaries beyond demonstrated capabilities.

---

## Detection Surface Analysis

### What Each Tier Sees

```
┌─────────────────────────────────────────────────────────────┐
│ Internet Infrastructure (BGP, DNS Root, Major IXs)          │ ← Tier 3
├─────────────────────────────────────────────────────────────┤
│ Recursive DNS Resolvers (8.8.8.8, 1.1.1.1, ISP)            │ ← Tier 2/3
├─────────────────────────────────────────────────────────────┤
│ ISP/Cloud Provider Netflow                                  │ ← Tier 1/2
├─────────────────────────────────────────────────────────────┤
│ Commercial Threat Intelligence Feeds                        │ ← Tier 1
├─────────────────────────────────────────────────────────────┤
│ Public-facing Services                                      │ ← Tier 0
└─────────────────────────────────────────────────────────────┘
```

**Key Insight**: Higher tiers have **cumulative visibility** — they see everything lower tiers see, plus more.

---

## Correlation Capabilities by Tier

### Tier 1: Automated Multi-Source
- DNS + IP + AS correlation
- Reputation-based alerting
- Historical lookups (months)
- **Threshold**: 2-3 correlated signals trigger alerts

### Tier 2: Manual + Automated
- All Tier 1 capabilities
- Custom signatures per-adversary
- Multi-year historical analysis
- Code similarity clustering
- **Threshold**: 3-5 correlated signals for high-confidence attribution

### Tier 3: Omniscient Correlation
- All Tier 2 capabilities
- Cross-organization correlation (link operations across targets)
- Decades of historical data
- Behavioral attribution via long-term patterns
- **Threshold**: Probabilistic attribution across vast dataset

---

## Threat Modeling Methodology

### Step 1: Identify Your Adversary Tier
Ask:
- What is the **value of your operation** to an adversary?
- What **resources** would they dedicate to finding you?
- What **legal/organizational constraints** do they face?

Examples:
- **Gray-market service**: Tier 1 (commercial threat intel, law enforcement)
- **Nation-state target**: Tier 2-3 (APT, SIGINT)
- **Activist/journalist**: Tier 2-3 (depends on adversary government capabilities)

### Step 2: Map Your Detectable Signals
For each layer (userland, DNS, routing, metadata):
- What signals do you emit?
- Which tier can observe them?
- What is the correlation potential?

Use the **OPSEC Failure Taxonomy** (docs/opsec-failure-taxonomy.md) as a checklist.

### Step 3: Model Correlation Attacks
Ask:
- Which 2-3 signals, if correlated, would defeat your OPSEC?
- Which tier has visibility into those signals?
- What is the detection probability?

### Step 4: Prioritize Mitigations
Focus on:
1. **High-correlation, high-visibility signals** (e.g., DNS sinkhole hits)
2. **Cross-layer leaks** (e.g., VPN AS + DNS resolver AS mismatch)
3. **Temporal patterns** (underestimated by most operators)

### Step 5: Accept Residual Risk
Against Tier 3, perfect OPSEC is infeasible. Define:
- **Acceptable detection probability**: What threshold can you tolerate?
- **Attribution cost**: How expensive do you make it to identify you?
- **Operational security**: Compartmentalization, burn plans, contingencies

---

## Case Study: Real-World Threat Models

### Case 1: Tor Hidden Service Operator
**Adversary**: Law enforcement (Tier 2), potentially NSA (Tier 3)

**Visible Signals**:
- Hidden service descriptor publication (timing, uptime patterns)
- Guard relay selection (limited pool, may be monitored)
- Traffic timing correlation (if adversary controls entry/exit nodes)
- Operational patterns (update schedule, content changes)
- Server infrastructure (if not airgapped, may leak via server-side signals)

**Correlation Attacks**:
- **Timing correlation**: Match hidden service uptime with operator's online patterns
- **Guard relay compromise**: Deanonymize via controlled entry nodes
- **Traffic analysis**: Size/timing sidechannel despite Tor encryption
- **Operational OPSEC failures**: Clearnet registrations, hosting account linkage

**Mitigations**:
- Bridge relays, guard selection hardening
- Temporal obfuscation (randomized uptime, automated operations)
- Infrastructure compartmentalization (no linkage to operator identity)
- Assume Tier 3 has guard relay visibility (no perfect anonymity)

---

### Case 2: APT Malware C2 Infrastructure
**Adversary**: Commercial threat intel (Tier 1), threat hunters (Tier 2)

**Visible Signals**:
- Domain registration patterns (registrar, creation date, WHOIS privacy)
- SSL certificate characteristics (issuer, Common Name, validity period)
- Hosting provider (AS, geographic region)
- DNS query patterns from infected endpoints
- C2 protocol behaviors (beaconing interval, traffic patterns)

**Correlation Attacks**:
- **Passive DNS**: Historical domain-IP associations link campaigns
- **SSL certificate clustering**: Shared certs across infrastructure
- **Sinkhole detection**: Queried domains hit threat intel feeds
- **AS reputation**: Bulletproof hosting providers flagged
- **Temporal patterns**: Domain lifespan, infrastructure rotation cadence

**Mitigations**:
- Ephemeral infrastructure (short-lived domains, rapid rotation)
- Diverse hosting (multiple providers, ASes, geographic regions)
- SSL certificate hygiene (unique per-domain, avoid reuse)
- Sinkhole awareness (monitor threat feeds, avoid flagged indicators)
- Behavioral diversity (randomized beaconing, protocol variations)

---

### Case 3: Journalist Source Communication
**Adversary**: State intelligence service (Tier 3)

**Visible Signals**:
- Communication timing (correlates with journalist's online presence)
- Network path (source location → journalist)
- Linguistic patterns (writing style, language)
- Operational security mistakes (metadata in documents, timezone leaks)

**Correlation Attacks**:
- **Timing analysis**: Match source communication with known suspects' online patterns
- **Network surveillance**: ISP-level monitoring of journalist's contacts
- **Document metadata**: Embedded creation time, software version, printer tracking dots
- **Behavioral analysis**: Writing style matches known individuals

**Mitigations**:
- SecureDrop or similar air-gapped submission systems
- Tor with bridge relays (avoid ISP detection)
- Metadata stripping (exiftool, pdf-redact-tools)
- Temporal obfuscation (delay submissions, randomized timing)
- Linguistic anonymization (style transfer, avoid unique phrases)
- **Accept residual risk**: Against Tier 3, focus on plausible deniability, not perfect anonymity

---

## Detection Probability Matrix

| Tier | Single Weak Signal | 2 Correlated Signals | 3+ Correlated Signals | Unique Signature |
|------|-------------------|---------------------|---------------------|-----------------|
| **Tier 1** | Low (noisy alerts) | Medium (automated flagging) | High (alert escalation) | **Critical** (immediate attribution) |
| **Tier 2** | Low (manual review queue) | High (analyst investigation) | **Critical** (high-confidence attribution) | **Critical** (definitive attribution) |
| **Tier 3** | Medium (archived for future) | High (probabilistic clustering) | **Critical** (cross-operation correlation) | **Critical** (retroactive analysis) |

**Key Insight**: Once you hit **3+ correlated signals**, attribution probability exceeds operational thresholds for Tier 2/3 adversaries.

---

## OPSEC Strategy by Tier

### Against Tier 1: Break Single-Source Detection
- Avoid sinkholed domains
- Minimize passive DNS footprint
- AS reputation hygiene
- **Goal**: Don't trigger automated alerts

### Against Tier 2: Break Correlation Chains
- Compartmentalize infrastructure
- Diverse tooling (avoid signatures)
- Temporal obfuscation
- Cross-layer signal minimization
- **Goal**: Force resource-intensive manual analysis, reduce confidence

### Against Tier 3: Maximize Attribution Cost
- Accept detection as inevitable
- Focus on plausible deniability
- Compartmentalization (limit blast radius)
- Long-term operational discipline
- **Goal**: Make attribution expensive enough that you're below operational priority threshold

---

## Operational Security Principles

### 1. **Defense in Depth Across Layers**
No single layer provides perfect OPSEC. Stack mitigations:
- Userland: Environment sanitization, TLS randomization
- DNS: Private resolvers, DoH hardening, sinkhole avoidance
- Routing: Multi-AS presence, BGP diversity
- Metadata: Temporal randomization, automated operations

### 2. **Assume Compromise, Limit Blast Radius**
Design operations such that:
- Single infrastructure compromise doesn't reveal entire operation
- Attribution of one component doesn't link to others
- Operational failures are compartmentalized

### 3. **Continuous Threat Intelligence**
Monitor what adversaries can see:
- Track your own infrastructure in passive DNS
- Monitor BGP announcements for your ASes
- Check sinkhole feeds for your domains
- Audit for temporal patterns

### 4. **Operational Discipline**
Human errors defeat technical OPSEC:
- No reuse of identities across operations
- No operational communications on infrastructure networks
- Development/testing fully separated from production
- Burn plans for infrastructure compromise

---

## Conclusion

**OPSEC is not binary.** It's a spectrum of:
- **Adversary capabilities** (what can they see?)
- **Correlation potential** (how easily do signals combine?)
- **Detection probability** (what's the chance of attribution?)

CHANAKYA provides the framework to:
1. **Understand your adversary** (capability tiers)
2. **Enumerate your signals** (failure taxonomy)
3. **Model correlation attacks** (cross-layer analysis)
4. **Design mitigations** (raise attribution cost)

**Against Tier 3, perfect OPSEC is impossible. The goal is to be expensive enough to deprioritize.**

---

*शत्रुः प्रायेण दुर्बुद्धिर्निश्चितं दुर्बलः सदा। स्वभावादेव कौन्तेय न बुद्ध्या न पराक्रमात्॥*

"The enemy is often foolish, always weak. By nature, not by intellect, not by valor."

**Do not assume your adversary is weak. Assume they are Tier 3. Design accordingly.**
