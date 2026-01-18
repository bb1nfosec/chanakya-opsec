# GEOINT Attribution & Geospatial Correlation

## Overview

Geospatial Intelligence (GEOINT) correlates **geographic signals** from IP geolocation, timezone inference, satellite imagery, and physical presence indicators.

**Key Insight**: Geography is destiny. Every signal has a location.

---

## Multi-Source Timezone Inference

### Bayesian Timezone Fusion

**Input Sources**:
1. IP Geolocation (city-level)
2. System timezone (`TZ` environment variable)
3. Activity timing patterns
4. Social media posts
5. GitHub commit times

**Fusion**:
```python
def infer_timezone_bayesian(signals):
    """
    Combine multiple timezone indicators
    Returns posterior probability distribution over timezones
    """
    prior = uniform_distribution(timezones)
    
    for signal in signals:
        likelihood = P(signal | timezone)
        posterior = prior * likelihood
        prior = normalize(posterior)
    
    return argmax(posterior)

# If P(UTC+1) > 0.8 → HIGH CONFIDENCE: Central Europe
```

**Attribution Weight**: V=0.85, R=0.8, C=0.9 → **AW=0.61 (HIGH)**

---

## IP Geolocation Correlation

**Databases**: MaxMind, IP2Location

**Accuracy**: City-level (80%+), Country (95%+)

**Cross-INT**:
- IP → Stockholm
- Timezone → UTC+1
- Activity → Evenings (18:00-02:00 UTC)
- **Conclusion**: Swedish operator, likely evening hobby project

**Attribution Weight**: V=0.8, R=0.7, C=0.75 → **AW=0.42 (MEDIUM)**

---

## Satellite Imagery Intelligence

**Use Case**: Physical infrastructure identification.

**Sources**:
- Google Earth (public)
- Commercial satellites (Planet Labs, Maxar)
- Government (classified)

**Example**:
```
IP 203.0.113.42 → Stockholm data center
BGP: AS64512 (Swedish ISP)
Satellite: Coordinates 59.3293°N, 18.0686°E
→ Physical building identified
```

**Attribution Weight**: V=0.6, R=0.7, C=0.7 → **AW=0.29 (MEDIUM)**

---

## Cell Tower Triangulation

**Method**: 3+ cell towers → position (10-100m accuracy)

**SIGINT + GEOINT Fusion**:
- IMSI catcher → cell IDs
- Triangulation → coordinates
- Satellite imagery → building identification

**Attribution Weight**: V=0.9, R=0.85, C=0.95 → **AW=0.73 (HIGH)**

---

## Cross-INT GEOINT Correlations

### GEOINT + OSINT + HUMINT
```
1. IP Geolocation: Stockholm
2. LinkedIn: Team members in Stockholm
3. Conference photo EXIF: GPS → Stockholm
4. Satellite imagery: Office building confirmed
→ FULL PHYSICAL ATTRIBUTION
```

---

*இடமே வலிமை*

"Location is strength."

**Know where they are. Know who they are.**
