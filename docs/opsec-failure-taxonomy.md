# OPSEC Failure Taxonomy

## Purpose

This document classifies OPSEC failures by **root cause**, **detection surface**, and **correlation potential**.

Understanding *how* OPSEC fails is more valuable than checklists of "what to do."

---

## Classification Framework

OPSEC failures are classified across three dimensions:

### 1. **Layer of Failure**
Where the leak originates:
- **L-USER**: Userland (applications, binaries, process behavior)
- **L-KERN**: Kernel-adjacent (observable OS side-effects)
- **L-DNS**: DNS (resolution, recursion, sinkholes)
- **L-NET**: Network/Routing (BGP, AS-path, traffic analysis)
- **L-META**: Metadata/Temporal (timing, patterns, habits)

### 2. **Correlation Potential**
How easily this signal combines with others:
- **C-SOLO**: Attributable on its own (e.g., hardcoded name in binary)
- **C-PAIR**: Requires 2 signals to correlate (e.g., DNS + timezone)
- **C-MULTI**: Requires 3+ signals, but strong when combined
- **C-WEAK**: Rarely sufficient even with other signals

### 3. **Detectability**
How easy it is for an adversary to observe:
- **D-TRIVIAL**: Passive observation (e.g., BGP announcements)
- **D-MODERATE**: Requires infrastructure access (e.g., DNS resolver logs)
- **D-HARD**: Requires active probing or privileged access
- **D-RESEARCH**: Requires novel techniques or side-channels

---

## Taxonomy

### **Category 1: Userland Signal Leakage** (L-USER)

#### 1.1 Binary Fingerprinting
**Description**: Unique characteristics of compiled binaries enable attribution

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Compilation timestamp** | Binary compiled at `2024-03-15T14:23:08 UTC` correlates to developer timezone | L-USER | C-PAIR | D-TRIVIAL |
| **Compiler version fingerprint** | GCC 11.2.0 with specific flags → toolchain identification | L-USER | C-MULTI | D-MODERATE |
| **Build path leakage** | Debug symbols contain `/home/username/project/` | L-USER | C-SOLO | D-TRIVIAL |
| **Entropy analysis** | High-entropy sections suggest packing/obfuscation tools | L-USER | C-MULTI | D-MODERATE |
| **Library static linking** | Specific glibc version statically linked → OS/toolchain | L-USER | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Medium (reproducible builds, stripped binaries, timestamp normalization)

---

#### 1.2 Environment Leakage
**Description**: Runtime environment artifacts reveal operator context

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Locale/language settings** | `LANG=en_IN.UTF-8` → geographic/cultural hint | L-USER | C-PAIR | D-TRIVIAL |
| **Timezone artifacts** | Log timestamps in `IST (UTC+5:30)` | L-USER | C-PAIR | D-TRIVIAL |
| **Font enumeration** | Specific font list → desktop environment/OS | L-USER | C-MULTI | D-MODERATE |
| **Environment variables** | `$HOME`, `$USER`, hostnames leaked in error messages | L-USER | C-SOLO | D-TRIVIAL |
| **Default paths** | Hardcoded `/home/user/...` or `C:\Users\...` | L-USER | C-PAIR | D-TRIVIAL |

**Mitigation Complexity**: Low (environment sanitization)

---

#### 1.3 Process Behavior Patterns
**Description**: Observable process behavior enables workload identification

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Syscall frequency distribution** | High `read()`/`write()` ratio → data processing vs. network service | L-USER/L-KERN | C-MULTI | D-RESEARCH |
| **Memory allocation patterns** | Large contiguous allocations → specific algorithm (e.g., ML model) | L-USER | C-MULTI | D-HARD |
| **File I/O patterns** | Sequential vs. random access → database vs. log processing | L-USER | C-MULTI | D-MODERATE |
| **Child process spawning** | Specific fork/exec patterns → framework identification | L-USER | C-MULTI | D-MODERATE |

**Mitigation Complexity**: High (behavior normalization, decoy processes)

---

#### 1.4 TLS/Application Layer Fingerprinting
**Description**: TLS handshake and application behavior reveal client/library

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **JA3/JA4-style fingerprints** | Cipher suite order + extensions → client library version | L-USER/L-NET | C-PAIR | D-TRIVIAL |
| **HTTP/2 priority frames** | Priority pattern unique to browser/library | L-USER | C-MULTI | D-MODERATE |
| **ALPN negotiation order** | Protocol preference → client implementation | L-USER | C-MULTI | D-MODERATE |
| **SNI leakage** | Domain name in plaintext (pre-ECH) | L-USER | C-SOLO | D-TRIVIAL |
| **Certificate validation behavior** | Pinning failures, CA trust choices | L-USER | C-MULTI | D-HARD |

**Mitigation Complexity**: Medium (custom TLS stacks, randomized parameters)

---

### **Category 2: Kernel-Adjacent Observable Leakage** (L-KERN)

#### 2.1 Timing Side-Channels
**Description**: Observable timing patterns leak system/workload characteristics

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Clock drift** | TSC drift patterns → CPU/hypervisor identification | L-KERN | C-MULTI | D-RESEARCH |
| **Scheduling jitter** | Task scheduling delay distribution → kernel version/load | L-KERN | C-MULTI | D-RESEARCH |
| **Interrupt timing** | Hardware interrupt patterns → device fingerprinting | L-KERN | C-MULTI | D-RESEARCH |
| **Context switch overhead** | Switch latency → CPU architecture/VM | L-KERN | C-MULTI | D-RESEARCH |

**Mitigation Complexity**: Very High (requires kernel modifications or VM tuning)

---

#### 2.2 Network Stack Behavior
**Description**: OS network stack implementation details are observable

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **TCP initial window size** | Specific default → OS identification | L-KERN/L-NET | C-MULTI | D-TRIVIAL |
| **TCP options ordering** | Option permutation → OS/kernel version | L-KERN/L-NET | C-PAIR | D-TRIVIAL |
| **IPID generation** | Incremental vs. random → OS fingerprint | L-KERN/L-NET | C-MULTI | D-TRIVIAL |
| **MTU discovery behavior** | PMTUD implementation → OS/kernel | L-KERN/L-NET | C-MULTI | D-MODERATE |
| **Congestion control algorithm** | CUBIC vs. BBR vs. Reno → kernel version | L-KERN/L-NET | C-MULTI | D-MODERATE |

**Mitigation Complexity**: High (requires kernel parameters tuning or custom stack)

---

#### 2.3 Entropy & RNG Behavior
**Description**: Random number generation patterns leak implementation details

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **RNG timing patterns** | `/dev/urandom` read latency → entropy source | L-KERN | C-MULTI | D-RESEARCH |
| **PRNG implementation** | Statistical bias → library/OS RNG | L-KERN/L-USER | C-MULTI | D-HARD |
| **Entropy pool behavior** | Blocking vs. non-blocking behavior | L-KERN | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Medium (use specific RNG libraries, add entropy)

---

### **Category 3: DNS OPSEC Failures** (L-DNS)

#### 3.1 Resolver Correlation
**Description**: DNS resolver choice and behavior enables infrastructure attribution

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Recursive resolver IP** | Queries from `8.8.8.8` → links all traffic to that resolver | L-DNS | C-PAIR | D-TRIVIAL |
| **Resolver AS mismatch** | VPN in AS64512, DNS queries from AS15169 (Google) | L-DNS/L-NET | C-PAIR | D-TRIVIAL |
| **Resolver choice consistency** | Always using same resolver → persistent infrastructure | L-DNS | C-MULTI | D-MODERATE |
| **DoH/DoT fallback** | DoH fails → plaintext fallback observed | L-DNS | C-SOLO | D-MODERATE |
| **Split-horizon exposure** | Internal domain queries leak to public resolver | L-DNS | C-SOLO | D-MODERATE |

**Mitigation Complexity**: Medium (careful resolver selection, DoH/DoT hardening)

---

#### 3.2 DNS Sinkhole Detection
**Description**: Threat intelligence sinkholes tag infrastructure as malicious

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Sinkhole NXDOMAIN pattern** | Query returns sinkhole IP → reputation tagging | L-DNS | C-SOLO | D-TRIVIAL |
| **Passive DNS correlation** | Historical queries link to known malicious infrastructure | L-DNS | C-PAIR | D-MODERATE |
| **DGA detection** | Algorithmically generated domain queries → malware signature | L-DNS | C-SOLO | D-MODERATE |
| **Typo/testing queries** | Common development typos (e.g., `exampl.com`) | L-DNS | C-MULTI | D-MODERATE |

**Mitigation Complexity**: High (requires sinkhole awareness, query hygiene)

---

#### 3.3 Query Timing & Ordering
**Description**: DNS query patterns correlate to application behavior

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Query ordering** | Specific domain resolution order → application identification | L-DNS | C-MULTI | D-MODERATE |
| **Query timing correlation** | DNS query timing matches network flow timing → session correlation | L-DNS/L-NET/L-META | C-PAIR | D-MODERATE |
| **TTL preference** | Specific TTL respect/ignore behavior → resolver implementation | L-DNS | C-MULTI | D-HARD |
| **Query frequency** | High query rate → scanning/automated behavior | L-DNS | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Medium (query randomization, caching strategy)

---

#### 3.4 Passive DNS Reconstruction
**Description**: Historical DNS data enables infrastructure mapping

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Domain-IP linkage** | Historical association of domain to specific IP/AS | L-DNS/L-NET | C-PAIR | D-MODERATE |
| **Infrastructure evolution** | Tracking domain migrations across IPs → operational patterns | L-DNS/L-META | C-MULTI | D-MODERATE |
| **Co-hosted domain discovery** | Multiple domains resolving to same IP → shared infrastructure | L-DNS | C-MULTI | D-MODERATE |

**Mitigation Complexity**: High (rotating infrastructure, ephemeral domains)

---

### **Category 4: Routing & Network Plane Failures** (L-NET)

#### 4.1 AS-Path Exposure
**Description**: BGP routing metadata reveals geographic and organizational context

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **VPN/Proxy AS** | Traffic exits via specific AS → provider identification | L-NET | C-PAIR | D-TRIVIAL |
| **AS reputation** | AS tagged as malicious/bulletproof → reputation correlation | L-NET | C-MULTI | D-TRIVIAL |
| **AS-path length** | Path length indicates geographic distance | L-NET | C-MULTI | D-MODERATE |
| **AS border crossing** | Traffic crosses specific IX/peering → localization | L-NET | C-MULTI | D-HARD |

**Mitigation Complexity**: Very High (requires multi-AS presence, BGP control)

---

#### 4.2 BGP Routing Behavior
**Description**: BGP announcements and updates leak operational patterns

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **BGP update timing** | Prefix announcements correlate with operational events | L-NET/L-META | C-PAIR | D-MODERATE |
| **Route flapping** | Instability patterns → infrastructure reliability | L-NET | C-MULTI | D-MODERATE |
| **Anycast selection** | Anycast node choice reveals true geolocation | L-NET | C-MULTI | D-MODERATE |
| **Prefix size** | Specific prefix allocation → organizational size | L-NET | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Very High (requires autonomous BGP control)

---

#### 4.3 Traffic Analysis
**Description**: Observable network traffic patterns enable correlation

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Packet size distribution** | Encrypted traffic size patterns → protocol/application | L-NET | C-MULTI | D-MODERATE |
| **Inter-packet timing** | Timing patterns → workload type, human vs. automated | L-NET/L-META | C-MULTI | D-MODERATE |
| **Flow duration** | Connection longevity → session type (streaming vs. transactional) | L-NET | C-MULTI | D-MODERATE |
| **Burst patterns** | Traffic bursting → batch processing vs. interactive | L-NET | C-MULTI | D-MODERATE |

**Mitigation Complexity**: High (traffic shaping, padding, decoy traffic)

---

#### 4.4 Path Asymmetry & MTU
**Description**: Routing asymmetry and path characteristics leak network topology

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Inbound/outbound path difference** | Asymmetric routing → multi-homed infrastructure | L-NET | C-MULTI | D-HARD |
| **MTU fingerprinting** | Specific MTU values → network path type (DSL, cable, fiber) | L-NET | C-MULTI | D-MODERATE |
| **Fragmentation behavior** | How fragmentation is handled → network equipment | L-NET | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Very High (requires network infrastructure control)

---

### **Category 5: Metadata & Temporal Failures** (L-META)

#### 5.1 Activity Timing Patterns
**Description**: When operations occur leaks human and organizational context

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Timezone correlation** | Activity always during 09:00-17:00 UTC+5:30 → geographic attribution | L-META | C-PAIR | D-TRIVIAL |
| **Weekday/weekend patterns** | No weekend activity → manual operations, not automated | L-META | C-MULTI | D-MODERATE |
| **Holiday patterns** | Downtime during specific cultural holidays → cultural attribution | L-META | C-MULTI | D-MODERATE |
| **Response latency** | Time between event and response → automation level | L-META | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Medium (automation, randomized scheduling, multi-timezone operations)

---

#### 5.2 Operational Cadence
**Description**: Predictable operational rhythm enables long-term correlation

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Update schedule** | Infrastructure updates every Tuesday 02:00 UTC | L-META | C-MULTI | D-MODERATE |
| **Release cadence** | Software releases every 2 weeks → team size/velocity estimation | L-META | C-MULTI | D-MODERATE |
| **Session duration patterns** | Consistent 8-hour sessions → human work shifts | L-META | C-MULTI | D-MODERATE |

**Mitigation Complexity**: Medium (randomized schedules, automation)

---

#### 5.3 Behavioral Fingerprints
**Description**: Operational habits create unique signatures

| Failure Mode | Example | Layer | Correlation | Detectability |
|-------------|---------|-------|-------------|---------------|
| **Git commit patterns** | Commit times correlate with infrastructure changes | L-META | C-PAIR | D-TRIVIAL |
| **Error message timing** | When errors occur → testing phase vs. production | L-META | C-MULTI | D-MODERATE |
| **Retry behavior** | Specific retry intervals/strategies → application framework | L-META | C-MULTI | D-HARD |

**Mitigation Complexity**: High (operational hygiene, decoupling development from production)

---

## Cross-Layer Correlation Examples

### Example 1: **VPN + DNS Correlation Attack**

| Signal | Layer | Observable |
|--------|-------|-----------|
| VPN exit AS | L-NET | AS64512 (MullvadVPN) |
| DNS queries | L-DNS | All via `8.8.8.8` (AS15169 - Google) |
| **Correlation** | **L-NET + L-DNS** | **VPN and DNS resolver in different ASes → split routing → misconfigurartion** |
| **Attribution Risk** | **HIGH** | Narrow set of users with this specific misconfiguration, linkable across sessions |

**Lesson**: Even "perfect" VPN use fails when DNS leaks to a different AS.

---

### Example 2: **Temporal + Geographic Correlation**

| Signal | Layer | Observable |
|--------|-------|-----------|
| Binary compilation timestamp | L-USER | `2024-03-15 14:23:08 UTC` |
| Activity timing | L-META | Operations always 09:00-17:00 UTC+5:30 |
| **Correlation** | **L-USER + L-META** | **Compilation at 14:23 UTC = 19:53 IST (evening) → Indian developer** |
| **Attribution Risk** | **MEDIUM** | Narrows to specific timezone, cultural context |

**Lesson**: Timestamps and timing patterns correlate to human geography.

---

### Example 3: **DNS + Routing + Timing Correlation**

| Signal | Layer | Observable |
|--------|-------|-----------|
| DNS query to sinkholed domain | L-DNS | Query to known DGA domain → tagged as malicious |
| BGP AS-path | L-NET | AS announcement from known bulletproof hosting |
| Activity cadence | L-META | Operations only during UTC+3 business hours |
| **Correlation** | **L-DNS + L-NET + L-META** | **High-confidence malicious infrastructure attribution** |
| **Attribution Risk** | **CRITICAL** | Three independent signals → operational threshold exceeded |

**Lesson**: Multi-layer correlation creates high-confidence attribution.

---

## Mitigation Complexity Matrix

| Layer | Low Complexity | Medium Complexity | High Complexity | Very High Complexity |
|-------|---------------|-------------------|-----------------|---------------------|
| **L-USER** | Environment sanitization | TLS fingerprint randomization | Behavior normalization | - |
| **L-KERN** | - | Entropy tuning | Network stack parameters | Kernel modifications |
| **L-DNS** | - | Resolver selection, DoH | Sinkhole awareness, query hygiene | Private recursive infrastructure |
| **L-NET** | - | Traffic shaping | Multi-path routing | Autonomous BGP control |
| **L-META** | - | Randomized scheduling | Operational decoupling | Multi-timezone operations |

---

## Key Takeaways

1. **No single failure is fatal** — but **correlation is**
2. **Easy mitigations exist** (environment vars) — **but hard ones matter most** (DNS, routing, timing)
3. **Tier 3+ adversaries exploit cross-layer correlation** — single-layer defenses fail
4. **Temporal patterns are underestimated** — time leaks human context
5. **DNS and routing are critical** — most OPSEC guidance ignores them

---

*कालः पचति भूतानि कालः संहरते प्रजाः।*  
*Time devours all beings; time destroys all creatures.*

**In OPSEC, time is your enemy. Treat it as such.**
