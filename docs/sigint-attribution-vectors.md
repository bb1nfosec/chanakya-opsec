# SIGINT Attribution Vectors

## Overview

Signals Intelligence (SIGINT) analyzes **electromagnetic emissions** and **traffic patterns** to attribute operations even when content is encrypted.

**Key Insight**: Encrypted ≠ Invisible. Traffic patterns betray operational intent.

---

## Traffic Analysis (Encrypted Data)

### Protocol Fingerprinting

**Attack**: Identify application despite encryption.

**Techniques**:
- Packet size distribution
- Inter-packet timing
- Flow patterns

**ML Classification**:
```python
# 85-95% accuracy classifying encrypted traffic
features = [
    mean(packet_sizes),
    std(packet_sizes),
    packet_size_entropy,
    inter_packet_timing_mean,
    flow_duration
]

protocol = random_forest.predict(features)
# Output: "SSH", "HTTPS", "VPN", "Tor"
```

**Attribution Weight**: V=0.9, R=0.7, C=0.8 → **AW=0.50 (HIGH)**

---

### Tor Flow Correlation

**Attack**: Link Tor entry and exit despite encryption.

**Method**: Timing analysis correlates flows.

**Accuracy**: 80%+ with sufficient traffic samples.

**Attribution Weight**: V=0.7, R=0.5, C=0.8 → **AW=0.28 (MEDIUM)**

---

## Cellular Network SIGINT

### IMSI Catchers (Stingray)

**Attack**: Capture IMSI from phones, track location.

**Range**: 200m - 2km

**Data Collected**:
- IMSI number
- Phone number  
- Location (cell tower triangulation)
- SMS content (if unencrypted)

**Attribution Weight**: V=0.95, R=0.9, C=0.95 → **AW=0.81 (CRITICAL)**

---

## RF Emissions (TEMPEST)

**Attack**: Electromagnetic leakage from displays/keyboards.

**Range**: 10-100m

**Attribution Weight**: V=0.3, R=0.4, C=0.6 → **AW=0.07 (LOW - requires proximity)**

---

*நம்பிக்கை ஒளி*

"Trust is light."

**SIGINT sees the signals you didn't know you transmitted.**
