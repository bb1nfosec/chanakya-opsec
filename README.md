# CHANAKYA

> *知己知彼，百战不殆*  
>  
> "Know yourself and know your enemy, and you will never be defeated in a hundred battles."  
> — Sun Tzu, The Art of War

> *Кто владеет информацией, тот владеет миром*  
>  
> "Who controls information, controls the world."  
> — Russian Strategic Doctrine

**CHANAKYA** is not an OPSEC checklist.  
**CHANAKYA** is not a compliance framework.  
**CHANAKYA** is not a product.

CHANAKYA is a research framework for understanding **how operational security fails through emergent signal correlation across abstraction layers**.

---

## ⚖️ Legal Disclaimer

**🚨 IMPORTANT: READ BEFORE USE**

This repository is for **RESEARCH and EDUCATION ONLY**.

✅ **LAWFUL USE:**
- Academic research
- Authorized security testing
- Journalism & whistleblowing (lawful)
- Privacy protection from stalking/harassment
- Educational purposes

❌ **PROHIBITED USE:**
- Criminal activity (any jurisdiction)
- Terrorism or material support
- Malicious hacking
- Evasion of lawful prosecution for serious crimes
- Stalking, harassment, doxing

**YOU ARE 100% RESPONSIBLE FOR YOUR ACTIONS.**

- The maintainers bear **NO responsibility** for misuse
- "I learned it from CHANAKYA" is **NOT** a legal defense
- **No anonymity guarantee** — techniques may fail
- Laws vary by country — **know your local laws**

**High-Risk Jurisdictions:** China, Russia, Saudi Arabia, UAE, Iran, North Korea (content may be illegal)

**📧 Legal Compliance & Removal Requests:** bb1nfosec@protonmail.com

**📄 Full Legal Terms:** See **[LEGAL.md](LEGAL.md)** for complete disclaimer, DMCA procedures, and removal request process.

**By using this repository, you acknowledge that you have read and agree to these terms.**

---

## The Problem

Modern OPSEC guidance focuses on isolated controls:
- "Use Tor"
- "Encrypt everything"
- "Disable JavaScript"
- "Use VPNs"

This is **checklist thinking**. It fails because:

1. **OPSEC failures are emergent** — weak signals across layers correlate to create strong attribution.
2. **Detection happens holistically** — adversaries don't analyze DNS *or* routing *or* timing. They analyze DNS *and* routing *and* timing *and* metadata.
3. **"Best practices" encode assumptions** — those assumptions leak through their absence or presence.
4. **Encryption hides content, not context** — and context is often sufficient for attribution.

**Reality**: Nation-state adversaries and sophisticated threat hunters don't rely on single indicators. They build **correlation graphs** across:
- Network plane (BGP, AS-path, anycast behavior)
- DNS plane (resolver chains, sinkhole patterns, recursion leakage)
- Userland signals (TLS fingerprints, binary entropy, timezone leaks)
- Kernel-adjacent observables (syscall patterns, timing jitter)
- Metadata & temporal patterns (activity cadence, update rhythms, human habits)

When two weak signals correlate, **OPSEC is already broken**.

---

## What CHANAKYA Does

CHANAKYA provides:

### 1. **Multi-Layer Signal Modeling**
Framework components for analyzing OPSEC failures across:
- **Userland**: Process behavior, binary fingerprints, environment leakage, application-layer signals
- **Kernel-Adjacent**: Observable side-effects without root (syscall patterns, timing, entropy sources)
- **DNS**: Resolver correlation, sinkhole detection, passive DNS reconstruction, split-horizon failures
- **Routing & Network Plane**: AS-path exposure, BGP asymmetry, traffic localization, MTU fingerprinting
- **Metadata & Temporal**: Activity patterns, timing fingerprints, operational habits

### 2. **Correlation Engine**
Models how weak signals across layers combine to create attribution:
- Cross-layer correlation detection
- Risk scoring based on signal intersection
- Detection probability modeling
- Deniability assessment

### 3. **Failure Scenario Simulations**
Demonstrates how real-world OPSEC configurations fail:
- DNS sinkhole attribution
- Routing asymmetry correlation
- Temporal pattern fingerprinting
- Environment leak chaining

### 4. **Strategic Documentation**
Not "how to be secure" — but "why security fails":
- OPSEC failure taxonomy
- Threat models based on adversary capabilities (not vendor marketing)
- Real-world case analysis
- Layer correlation methodologies

### 5. **AI-Era 2026 Enhancements** 🤖

**New**: Addressing AI/ML-augmented attribution threats:
- **AI-Augmented Attribution**: How Graph ML, LSTMs, and LLMs enable retrospective attribution
- **Quantitative Signal Scoring**: Mathematical framework for attribution weight calculation (V × R × C formula)
- **Retrospective Attribution Simulation**: Demonstrating how "safe" signals become dangerous years later
- **Kernel-Adjacent Analysis**: Syscall patterns, timing side-channels, workload classification
- **Behavioral Entropy Quantification**: Shannon entropy (H > 3.5 bits target) for unpredictability measurement
- **Counter-AI OPSEC**: Defensive techniques specifically designed against ML correlation

**Key Differentiator**: Only OPSEC framework addressing AI-era attribution explicitly with rigorous quantification.

### 6. **Multi-INT Intelligence Layers** 🌐🔍📡🗺️👥🔬

**New**: Comprehensive intelligence discipline analysis:

**🌐 Browser Layer**
- WebRTC IP leaks (CRITICAL - bypasses VPN/Tor)
- Canvas/WebGL fingerprinting (99.9% unique)
- Font enumeration, extension detection
- JavaScript timing attacks

**🔍 OSINT Layer**
- GitHub/GitLab metadata mining & commit timing correlation
- LinkedIn team structure inference
- Domain WHOIS correlation & passive DNS
- Conference attendance tracking
- Social media timing analysis

**📡 SIGINT Layer**
- Encrypted traffic analysis (despite TLS/VPN)
- Cellular network correlation (IMSI catchers)
- Tor flow correlation
- Protocol fingerprinting

**🗺️ GEOINT Layer**
- Multi-source timezone triangulation (Bayesian fusion)
- IP geolocation → satellite imagery correlation
- Cell tower triangulation
- Travel pattern analysis
- Physical infrastructure identification

**👥 HUMINT Layer**
- Behavioral profiling (work/life patterns)
- Language/cultural indicators in code
- Social engineering attack surface
- Conference badge photos → identity revelation
- Team structure analysis

**🔬 Forensics Layer**
- Filesystem forensics (MAC times, deleted file recovery)
- Memory forensics (RAM artifacts)
- Browser forensics (history, cookies)
- Network forensics (PCAP analysis)
- Metadata forensics (EXIF, document metadata)
- Timeline reconstruction

**Cross-INT Fusion**: Multi-discipline signal correlation (e.g., OSINT + GEOINT + HUMINT → full attribution)

**Key Innovation**: ONLY framework modeling realistic all-source intelligence fusion.

---

## Philosophy

CHANAKYA operates on these principles:

### **Adversarial Deniability Over Compliance**
The goal is not "follow standards" — it's "create ambiguity and misattribution."

### **Correlation Is Detection**
If two independent signals can be correlated to the same operation, OPSEC has failed.

### **Trust Nothing, Verify Leakage**
Every layer leaks. The question is not "if" but "what" and "how much."

### **Routing and DNS Are First-Class OPSEC Layers**
Most OPSEC guidance treats network infrastructure as solved. It's not. DNS and routing are where most sophisticated attribution happens.

### **Temporal Patterns Are Fingerprints**
Human habits leak through operational timing. Activity cadence, update patterns, and temporal correlation destroy anonymity.

### **No Kernel Exploitation, Only Observable Effects**
CHANAKYA focuses on side-channel observables that don't require root or kernel modules — the signals hiding in plain sight.

---

## Who This Is For

CHANAKYA assumes you already know:
- MITRE ATT&CK
- OWASP threat modeling
- Basic OPSEC principles
- Network fundamentals (TCP/IP, DNS, BGP)
- Unix/Linux userland and kernel concepts

This framework is for:
- **Red team operators** who need to understand how their infrastructure leaks
- **Threat hunters** who want to detect adversaries through weak signal correlation
- **Security researchers** studying attribution techniques
- **Intelligence analysts** modeling nation-state detection capabilities
- **Engineers building high-stakes systems** where OPSEC failure has real consequences

If you're looking for a scanner or a compliance tool, **this is not for you**.

---

## Structure

```
chanakya-opsec/
├── docs/                          # Strategic documentation
│   ├── # Core Documentation
│   ├── philosophy.md              # Core principles & threat philosophy
│   ├── threat-model.md            # Adversary capabilities (Tier 0-3.5)
│   ├── opsec-failure-taxonomy.md  # 50+ failure mode classification
│   ├── layer-correlation.md       # Cross-layer signal correlation
│   ├── real-world-case-analysis.md # Silk Road, AlphaBay, APT case studies
│   ├── # AI-Era Enhancements (2026)
│   ├── ai-augmented-attribution.md # Graph ML, LSTMs, retrospective attribution
│   ├── signal-scoring-methodology.md # V×R×C quantitative formula
│   ├── kernel-adjacent-signals.md # Syscall patterns, timing side-channels
│   ├── behavioral-entropy-analysis.md # Shannon entropy quantification
│   ├── counter-ai-opsec.md        # Defensive techniques vs. ML
│   ├── # Multi-INT Intelligence Layers
│   ├── browser-opsec-failures.md  # WebRTC leaks, Canvas fingerprinting
│   ├── osint-correlation-techniques.md # GitHub, LinkedIn, WHOIS correlation
│   ├── sigint-attribution-vectors.md # Traffic analysis, cellular tracking
│   ├── geoint-geospatial-correlation.md # Timezone triangulation, satellite
│   ├── humint-social-engineering.md # Behavioral profiling, conferences
│   ├── forensics-attribution-vectors.md # Filesystem, memory, EXIF
│   ├── # Advanced Operational Techniques
│   ├── anti-forensics-plausible-deniability.md # HiddenVM, amnesic OS
│   ├── financial-privacy-cryptocurrency.md # Monero, CoinJoin, chain analysis
│   ├── infrastructure-stealth-camouflage.md # Redirectors, Shodan evasion
│   ├── personal-opsec-checklist.md # Military-grade operational manual
│   └── index.html                 # MITRE-style interactive wiki
├── framework/                     # Analysis framework (9 modules)
│   ├── userland/                  # Binary fingerprints, TLS, environment leaks
│   ├── dns/                       # Resolver correlation, sinkhole detection
│   ├── routing/                   # BGP, AS-path, route asymmetry
│   ├── metadata/                  # Activity timing, operational cadence
│   └── correlation-engine/        # Multi-layer signal fusion
├── simulations/                   # Failure scenarios & demonstrations
│   ├── failure-scenarios/         # DNS sinkhole, temporal correlation
│   └── ai-era/                    # Retrospective attribution simulation
├── tests/                         # Test infrastructure
│   ├── test_attribution_scenarios.py # 5 realistic failure scenarios
│   └── personal_opsec_audit.py    # Pre-operation 5-minute audit
├── examples/                      # Reference implementations
├── CONTRIBUTING.md                # Git workflow & development guide
├── README.md                      # This file
├── SECURITY.md                    # Security & ethical use policy
└── requirements.txt               # Dependencies
```

---

## Non-Goals

CHANAKYA is **not**:
- ❌ Malware or exploitation tooling
- ❌ A penetration testing scanner
- ❌ A live attack infrastructure
- ❌ Legal or operational advice
- ❌ A product or commercial offering
- ❌ Suitable for compliance checkbox purposes

CHANAKYA **is**:
- ✅ Analysis, modeling, and education
- ✅ Research-grade OPSEC failure analysis
- ✅ A framework for understanding attribution
- ✅ Designed for senior engineers and researchers

---

## Getting Started

1. **Read the philosophy** → `docs/philosophy.md`
2. **Understand failure taxonomy** → `docs/opsec-failure-taxonomy.md`
3. **Model your threats** → `docs/threat-model.md`
4. **Pre-operation audit** → `python tests/personal_opsec_audit.py`
5. **Explore Multi-INT layers** → Browse `docs/` (23 strategic documents)
6. **Run framework** → `python examples/opsec_audit_example.py`
7. **Test attribution scenarios** → `python tests/test_attribution_scenarios.py`
8. **Interactive wiki** → Open `docs/index.html` in browser

---

## Contributing

**CHANAKYA is purely open source and designed to evolve through community contributions.**

This framework is yours to:
- ✅ Use for research, operations, education
- ✅ Fork and customize for your needs
- ✅ Extend with new analyzers and correlation techniques
- ✅ Improve and evolve collaboratively

### We Welcome Contributions Of:
- Novel OPSEC failure modes and case studies
- Additional layer analyzers (kernel-side channels, wireless, etc.)
- Cross-layer correlation algorithms
- Real-world attribution case studies (anonymized)
- Improved threat models and adversary TTPs
- Simulation scenarios and examples
- Documentation improvements
- Bug fixes and performance enhancements

### How to Contribute:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-opsec-analysis`)
3. Commit your changes (`git commit -m 'Add novel DNS correlation technique'`)
4. Push to the branch (`git push origin feature/amazing-opsec-analysis`)
5. Open a Pull Request

**No contribution is too small.** Typo fixes, documentation improvements, and clarifications are all valuable.

### Community Evolution Philosophy

CHANAKYA is designed to be a **living research framework** that evolves with the OPSEC landscape:
- Weekly updates with new failure modes
- Community-driven research additions
- Collaborative threat modeling
- Open knowledge sharing

**This is not a product. This is a movement toward honest, research-grade OPSEC analysis.**

---

## Legal & Ethical Notice

This framework is for **defensive research, education, and lawful security testing only**.

- Do not use CHANAKYA to conduct unauthorized surveillance or attacks
- Do not use CHANAKYA to violate laws or regulations
- Do not use CHANAKYA to harm individuals or organizations
- Researchers are responsible for ethical use and compliance with local laws

See `SECURITY.md` for full legal notices and responsible disclosure guidelines.

---

## License

**MIT License** — See [LICENSE](LICENSE)

**You are free to:**
- ✅ Use commercially
- ✅ Modify and adapt
- ✅ Distribute
- ✅ Use privately

**Under the terms:**
- Attribution appreciated (but not required)
- No warranty provided
- See SECURITY.md for ethical use guidelines

**This is purely open source.** Take it, evolve it, build upon it. The OPSEC research community benefits when knowledge flows freely.

---

## Citation

If you use CHANAKYA in your research or operations:

```bibtex
@misc{chanakya-opsec-2026,
  title={CHANAKYA: Multi-Layer OPSEC Failure Analysis Framework},
  author={bb1nfosec and contributors},
  year={2026},
  url={https://github.com/bb1nfosec/chanakya-opsec},
  note={Open-source research framework for operational security failure modeling and cross-layer signal correlation}
}
```

**Attribution appreciated but not required.** This is open source — use it, evolve it, share it.

---

## Acknowledgments

Inspired by:
- Classical intelligence doctrine and statecraft
- Modern signals intelligence (SIGINT) methodologies
- Decades of OPSEC failures in the wild
- The uncomfortable truth that most security theater fails under real scrutiny

---

*הידע כוח* (Ha'yeda koach)  
*Knowledge is power.*

CHANAKYA: Where signals converge, attribution emerges.
