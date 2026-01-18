# CHANAKYA

> *धर्मार्थकाममोक्षाणामुपायः सदुपेक्षते। त्रयीवार्ता दण्डनीतिश्चाङ्गानि यस्य दन्दिनः॥*
>  
> "He who understands the means to dharma, artha, kama, and moksha, who knows the Trayi, Varta, and Danda-niti — he commands the science of statecraft."

**CHANAKYA** is not an OPSEC checklist.  
**CHANAKYA** is not a compliance framework.  
**CHANAKYA** is not a product.

CHANAKYA is a research framework for understanding **how operational security fails through emergent signal correlation across abstraction layers**.

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
│   ├── philosophy.md              # Core principles & threat philosophy
│   ├── threat-model.md            # Adversary capabilities & detection methods
│   ├── opsec-failure-taxonomy.md  # Classification of OPSEC failures
│   ├── layer-correlation.md       # Cross-layer signal correlation
│   └── real-world-case-analysis.md # Case studies of OPSEC failures
├── framework/                     # Analysis framework components
│   ├── userland/                  # Userland signal analysis
│   ├── dns/                       # DNS OPSEC analysis
│   ├── routing/                   # Routing & network plane analysis
│   ├── metadata/                  # Metadata & temporal analysis
│   └── correlation-engine/        # Multi-layer correlation engine
├── simulations/                   # Failure scenarios & demonstrations
│   ├── failure-scenarios/         # Specific OPSEC failure simulations
│   └── signal-correlation/        # Correlation demonstrations
├── examples/                      # Reference implementations
├── README.md                      # This file
└── SECURITY.md                    # Security & legal notices
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
4. **Explore framework components** → `framework/`
5. **Run simulations** → `simulations/`

---

## Contributing

CHANAKYA evolves through research contributions. If you've identified:
- Novel OPSEC failure modes
- Cross-layer correlation techniques
- Real-world attribution case studies
- Improved threat models

See `CONTRIBUTING.md` (coming soon).

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

[To be determined — likely MIT or Apache 2.0 for research use]

---

## Citation

If you use CHANAKYA in your research:

```
@misc{chanakya-opsec,
  title={CHANAKYA: Multi-Layer OPSEC Failure Analysis Framework},
  year={2026},
  url={https://github.com/[username]/chanakya-opsec},
  note={Research framework for operational security failure modeling}
}
```

---

## Acknowledgments

Inspired by:
- Classical intelligence doctrine and statecraft
- Modern signals intelligence (SIGINT) methodologies
- Decades of OPSEC failures in the wild
- The uncomfortable truth that most security theater fails under real scrutiny

---

*असतो मा सद्गमय। तमसो मा ज्योतिर्गमय।*  
*From untruth, lead me to truth. From darkness, lead me to light.*
