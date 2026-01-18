# Quantitative Signal Scoring Methodology

## Overview

This document provides a rigorous, mathematical framework for scoring OPSEC signals based on their **attribution potential**.

Unlike qualitative risk assessment ("HIGH/MEDIUM/LOW"), this methodology assigns numerical scores enabling:
- Objective risk prioritization
- Quantitative OPSEC audits
- Computational risk modeling
- ML-based risk prediction

---

## Core Scoring Dimensions

Every OPSEC signal is scored across three independent dimensions:

### 1. **Visibility Score (V)** ∈ [0.0, 1.0]

**Definition**: Probability that an adversary of a given tier can observe this signal.

**Factors:**
- Network position (passive collection, active probing, privileged access)
- Data availability (public, commercial, nation-state only)
- Technical difficulty of extraction

**Examples:**

| Signal | Tier 1 | Tier 2 | Tier 3 | Explanation |
|--------|--------|--------|--------|-------------|
| DNS query to 8.8.8.8 | 0.1 | 0.8 | 1.0 | Google logs, ISP NetFlow, SIGINT |
| Source IP in web server log | 0.0 | 0.6 | 0.9 | Server compromise required |
| TLS SNI in cleartext | 0.2 | 0.9 | 1.0 | Passive network observation |
| Binary build timestamp | 0.0 | 0.7 | 0.9 | Requires binary acquisition |
| SSH key fingerprint | 0.0 | 0.5 | 0.8 | Requires server logs/access |

---

### 2. **Retention Score (R)** ∈ [0.0, 1.0]

**Definition**: Expected duration signal persists in adversary databases.

**Formula:**
```
R = min(1.0, log₁₀(retention_days) / log₁₀(3650))

Where:
- retention_days: Expected days signal remains in databases
- 3650 days (10 years): Maximum retention considered
```

**Examples:**

| Signal | Retention Period | R Score | Explanation |
|--------|-----------------|---------|-------------|
| Passive DNS record | 10+ years | **1.0** | Permanent in databases (Farsight, etc.) |
| BGP announcement | 5-10 years | **0.95** | Route collectors archive indefinitely |
| NetFlow summary | 90 days | **0.61** | ISPs retain for months |
| TLS cert transparency | Permanent | **1.0** | Public append-only logs |
| SSH failed login | 30 days | **0.47** | Short log retention |
| Web access log | 7-365 days | **0.34-0.83** | Varies by organization |

**Key Insight**: Signals with R > 0.8 are **permanent liabilities**. They can be correlated years later.

---

### 3. **Correlation Potential (C)** ∈ [0.0, 1.0]

**Definition**: How easily this signal links to other signals to create attribution chains.

**Correlation Types:**

#### **3.1 SOLO (C = 1.0)**
Signal alone is sufficient for attribution.

Examples:
- Known sinkholed domain query (immediate infrastructure linkage)
- Hardcoded C2 domain in malware sample
- Reused SSH key with known attribution

#### **3.2 PAIR (C = 0.7-0.9)**
Signal requires 1-2 other signals for attribution.

Examples:
- Source IP + DNS resolver AS mismatch
- TLS fingerprint + behavior pattern anomaly
- Timing pattern + timezone leak

#### **3.3 MULTI (C = 0.4-0.6)**
Signal requires 3-5 other signals.

Examples:
- Binary entropy (needs context: strings, behavior, network)
- Session duration pattern (needs many samples + other metadata)
- AS-path shape (needs temporal analysis + other network signals)

#### **3.4 WEAK (C = 0.1-0.3)**
Signal requires many other signals or advanced ML.

Examples:
- Single syscall timing measurement
- HTTP User-Agent string (common value)
- Generic error message

**Quantification Formula:**
```python
def correlation_potential(signal_type):
    if signal_type == "SOLO":
        return random.uniform(0.95, 1.0)
    elif signal_type == "PAIR":
        return random.uniform(0.7, 0.9)
    elif signal_type == "MULTI":
        return random.uniform(0.4, 0.6)
    elif signal_type == "WEAK":
        return random.uniform(0.1, 0.3)
```

---

## Attribution Weight Formula

The final **Attribution Weight (AW)** combines all three dimensions:

```
AW = V × R × C

Where:
- V: Visibility (tier-specific)
- R: Retention
- C: Correlation Potential

Result: AW ∈ [0.0, 1.0]
```

### Interpretation

| AW Range | Risk Level | Interpretation | Action Required |
|----------|-----------|----------------|------------------|
| **0.8-1.0** | **CRITICAL** | High visibility, permanent retention, strong correlation | **IMMEDIATE MITIGATION** |
| **0.6-0.79** | **HIGH** | Likely observable, long retention, good correlation | **PRIORITY MITIGATION** |
| **0.4-0.59** | **MEDIUM** | Moderate detectability and correlation | **MITIGATE IF FEASIBLE** |
| **0.2-0.39** | **LOW** | Difficult to observe or weak correlation | **MONITOR** |
| **0.0-0.19** | **MINIMAL** | Rare observation or negligible correlation | **ACCEPTABLE RISK** |

---

## Comprehensive Signal Scoring Table

### DNS Signals

| Signal | V (T2) | V (T3) | R | C | **AW (T2)** | **AW (T3)** | Risk |
|--------|--------|--------|---|---|------------|------------|------|
| Query to sinkholed domain | 0.95 | 1.0 | 0.95 | 1.0 | **0.90** | **0.95** | CRITICAL |
| Public DNS resolver (8.8.8.8) | 0.7 | 0.95 | 0.9 | 0.8 | **0.50** | **0.68** | HIGH |
| Resolver AS != VPN AS | 0.6 | 0.9 | 0.85 | 0.75 | **0.38** | **0.57** | MEDIUM-HIGH |
| DNS query timing pattern | 0.4 | 0.8 | 0.7 | 0.5 | **0.14** | **0.28** | LOW-MEDIUM |
| Rapid query sequence | 0.5 | 0.85 | 0.65 | 0.6 | **0.20** | **0.33** | MEDIUM |
| TTL fingerprint anomaly | 0.3 | 0.7 | 0.75 | 0.4 | **0.09** | **0.21** | LOW |

---

### Network/Routing Signals

| Signal | V (T2) | V (T3) | R | C | **AW (T2)** | **AW (T3)** | Risk |
|--------|--------|--------|---|---|------------|------------|------|
| BGP announcement | 0.9 | 1.0 | 0.95 | 0.6 | **0.51** | **0.57** | HIGH |
| AS-path contains high-risk AS | 0.85 | 0.95 | 0.9 | 0.7 | **0.54** | **0.60** | HIGH |
| Route asymmetry detected | 0.5 | 0.85 | 0.8 | 0.65 | **0.26** | **0.44** | MEDIUM |
| Consistent packet size | 0.3 | 0.7 | 0.5 | 0.4 | **0.06** | **0.14** | LOW |
| MTU fingerprint | 0.4 | 0.75 | 0.6 | 0.45 | **0.11** | **0.20** | LOW |

---

### Userland Signals

| Signal | V (T2) | V (T3) | R | C | **AW (T2)** | **AW (T3)** | Risk |
|--------|--------|--------|---|---|------------|------------|------|
| Hardcoded C2 in binary | 0.0 | 0.9 | 0.95 | 1.0 | **0.00** | **0.86** | CRITICAL (if binary obtained) |
| Binary build timestamp | 0.0 | 0.7 | 0.9 | 0.7 | **0.00** | **0.44** | MEDIUM (T3 only) |
| High binary entropy | 0.0 | 0.65 | 0.8 | 0.5 | **0.00** | **0.26** | LOW-MEDIUM |
| Timezone in environment | 0.3 | 0.75 | 0.7 | 0.8 | **0.17** | **0.42** | MEDIUM |
| TLS fingerprint (JA3) | 0.6 | 0.9 | 0.6 | 0.7 | **0.25** | **0.38** | MEDIUM |
| OS fingerprint | 0.5 | 0.85 | 0.5 | 0.55 | **0.14** | **0.23** | LOW |

---

### Metadata/Temporal Signals

| Signal | V (T2) | V (T3) | R | C | **AW (T2)** | **AW (T3)** | Risk |
|--------|--------|--------|---|---|------------|------------|------|
| Consistent activity window | 0.6 | 0.9 | 0.85 | 0.85 | **0.43** | **0.65** | MEDIUM-HIGH |
| Timezone correlation (multi-platform) | 0.4 | 0.85 | 0.9 | 0.9 | **0.32** | **0.69** | HIGH (T3) |
| Weekday-only pattern | 0.5 | 0.8 | 0.8 | 0.7 | **0.28** | **0.45** | MEDIUM |
| Predictable update cadence | 0.55 | 0.75 | 0.75 | 0.75 | **0.31** | **0.42** | MEDIUM |
| Session duration consistency | 0.4 | 0.7 | 0.6 | 0.5 | **0.12** | **0.21** | LOW |

---

## Tier-Specific Visibility Adjustments

### Tier 0-1: Script Kiddie / Opportunistic
```
V_T1 = base_visibility × 0.1
```
**Limited passive collection, no archived data access**

### Tier 2: Commercial Threat Intel / Manual APT
```
V_T2 = base_visibility × 0.6
```
**Passive DNS, commercial feeds, manual correlation**

### Tier 3: Nation-State SIGINT
```
V_T3 = base_visibility × 0.95
```
**Backbone monitoring, ISP partnerships, historical archives**

### Tier 3.5: AI-Augmented Nation-State
```
V_T3.5 = min(1.0, V_T3 × 1.1)
C_T3.5 = min(1.0, C × 1.3)  # AI amplifies correlation
```
**Real-time ML correlation, automated cross-platform fusion**

---

## Composite OPSEC Score

For an operation with n signals:

```
Composite Risk Score = 1 - ∏ᵢ₌₁ⁿ (1 - AWᵢ)

Interpretation:
- Score < 0.3: LOW overall risk
- Score 0.3-0.6: MEDIUM risk
- Score 0.6-0.8: HIGH risk
- Score > 0.8: CRITICAL risk (likely attribution)
```

**Example:**
```
Operation with 5 signals:
AW₁ = 0.90 (DNS sinkhole)
AW₂ = 0.50 (public DNS resolver)
AW₃ = 0.43 (consistent timing)
AW₄ = 0.38 (resolver AS mismatch)
AW₅ = 0.25 (TLS fingerprint)

Composite = 1 - (1-0.90)(1-0.50)(1-0.43)(1-0.38)(1-0.25)
          = 1 - (0.10 × 0.50 × 0.57 × 0.62 × 0.75)
          = 1 - 0.0133
          = 0.987 (98.7% risk)

→ CRITICAL: Attribution highly likely
```

---

## Signal Accumulation Over Time

Signals accumulate during operations. Model attribution risk growth:

```python
def attribution_confidence(t, signal_rate=0.5, adversary_efficiency=1.0):
    """
    t: time (days)
    signal_rate: signals discovered per day
    adversary_efficiency: Tier multiplier (T1=0.3, T2=0.7, T3=1.5)
    """
    signals = signal_rate * t
    λ = adversary_efficiency
    confidence = 1 - math.exp(-λ * signals)
    return confidence

# Tier 3 adversary, 0.5 signals/day:
confidence_30d = attribution_confidence(30, 0.5, 1.5)  # ≈ 99.9%
confidence_7d = attribution_confidence(7, 0.5, 1.5)    # ≈ 95.3%
```

**Takeaway**: Against Tier 3, operations leak ~0.5 signals/day → high attribution confidence within 1-2 weeks.

---

## Practical Application

### OPSEC Audit Workflow

1. **Enumerate signals** from your operation
2. **Score each signal** using V, R, C dimensions (tier-specific)
3. **Calculate AW** for each signal
4. **Prioritize mitigations** by AW (highest first)
5. **Calculate composite risk**
6. **Iterate** until composite risk < threshold

### Example Audit

**Operation**: Infrastructure access via VPN

**Signals Identified:**
```
1. DNS resolver: 8.8.8.8 (AW_T3 = 0.68) → HIGH
2. VPN AS: AS64512, DNS AS: AS15169 (AW_T3 = 0.57) → HIGH
3. Activity: 18:00-02:00 UTC weekdays (AW_T3 = 0.65) → HIGH
4. TLS fingerprint: OpenSSL 1.1.1 (AW_T3 = 0.38) → MEDIUM

Composite Risk (T3): 0.94 → CRITICAL
```

**Mitigations:**
```
1. Use DNS resolver in same AS as VPN → eliminates AW=0.57 signal
2. Randomize activity timing ±4 hours → reduces AW=0.65 to 0.35
3. Rotate VPN endpoints → reduces correlation potential

New Composite Risk: 0.73 → HIGH (still risky, but improved)
```

---

## Integration with Framework

### Python Implementation

```python
from dataclasses import dataclass
import math

@dataclass
class SignalScore:
    name: str
    visibility_t2: float  # 0.0-1.0
    visibility_t3: float  # 0.0-1.0
    retention: float      # 0.0-1.0
    correlation: float    # 0.0-1.0
    
    def attribution_weight(self, tier=3):
        """Calculate attribution weight for given tier"""
        v = self.visibility_t3 if tier >= 3 else self.visibility_t2
        return v * self.retention * self.correlation
    
    def risk_level(self, tier=3):
        """Get risk level classification"""
        aw = self.attribution_weight(tier)
        if aw >= 0.8:
            return "CRITICAL"
        elif aw >= 0.6:
            return "HIGH"
        elif aw >= 0.4:
            return "MEDIUM"
        elif aw >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"

def composite_risk(signals, tier=3):
    """Calculate composite risk from multiple signals"""
    product = 1.0
    for signal in signals:
        aw = signal.attribution_weight(tier)
        product *= (1 - aw)
    return 1 - product

# Example usage
dns_sinkhole = SignalScore(
    name="DNS sinkhole query",
    visibility_t2=0.95,
    visibility_t3=1.0,
    retention=0.95,
    correlation=1.0
)

print(f"AW (T3): {dns_sinkhole.attribution_weight(3):.2f}")
print(f"Risk: {dns_sinkhole.risk_level(3)}")
```

---

## Conclusion

Quantitative signal scoring enables:
- **Objective prioritization**: Fix highest AW signals first
- **Risk modeling**: Predict attribution probability over time
- **OPSEC audits**: Measure improvement numerically
- **ML integration**: Train models on scored signals

**Key Formulas:**
```
AW = V × R × C
Composite Risk = 1 - ∏(1 - AWᵢ)
Attribution Confidence(t) = 1 - exp(-λ × signals(t))
```

---

*கற்றது கைம்மண் அளவு, கல்லாதது உலகளவு.*

"What you have learned is a handful; what you have yet to learn is the size of the world."

**Measure what matters. Score what persists. Mitigate what correlates.**
