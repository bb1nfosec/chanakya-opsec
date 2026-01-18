# Behavioral Entropy Analysis

## Overview

**Behavioral entropy measures the unpredictability of operational patterns.**

Low entropy = predictable = easy to fingerprint  
High entropy = unpredictable = difficult to cluster

This document provides rigorous quantification of operational predictability using information

 theory.

---

## Shannon Entropy

**Formula**:
```
H(X) = -Σ p(xᵢ) log₂ p(xᵢ)

Where:
- p(xᵢ) = probability of event i
- H(X) ∈ [0, log₂(n)] bits
- n = number of possible events
```

**Interpretation**:
- H = 0: Perfectly predictable (always same event)
- H = log₂(n): Perfectly random (uniform distribution)

---

## Behavioral Patterns to Measure

### 1. **Activity Timing Entropy**

**Events**: Hour of day when active (0-23)

**Maximum Entropy**: log₂(24) ≈ 4.58 bits (uniform 24/7)

**Examples**:

| Pattern | Entropy | Classification |
|---------|---------|----------------|
| Always 18:00-19:00 | 0 bits | CRITICAL RISK |
| 18:00-02:00 weekdays | 2.1 bits | HIGH RISK |
| Random 14:00-22:00 | 3.0 bits | MEDIUM RISK |
| **Uniform 24/7** | **4.58 bits** | **LOW RISK** |

---

### 2. **Session Duration Entropy**

**Events**: Session length buckets (e.g., 1h, 2h, 3h...)

**Calculation**:
```python
def session_duration_entropy(durations):
    from collections import Counter
    import math
    
    # Bucket durations into hours
    bucketed = [int(d.total_seconds() / 3600) for d in durations]
    counts = Counter(bucketed)
    total = len(bucketed)
    
    entropy = 0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    
    return entropy
```

**Target**: H > 2.5 bits (varied session lengths)

---

### 3. **Update Cadence Entropy**

**Events**: Days between updates

**Low Entropy Example**:
```
Updates every Tuesday → H ≈ 0 bits (perfectly predictable)
```

**High Entropy Example**:
```
Updates every 3-10 days (random) → H ≈ 2.8 bits
```

---

## Composite Behavioral Fingerprint Score

**Combine multiple entropy measurements**:

```python
def behavioral_fingerprint_score(operational_data):
    """
    Returns score ∈ [0, 1]
    0 = highly fingerprintable (low entropy)
    1 = difficult to fingerprint (high entropy)
    """
    
    # Calculate individual entropies
    timing_entropy = calculate_timing_entropy(operational_data['activity_times'])
    session_entropy = calculate_session_entropy(operational_data['session_durations'])
    cadence_entropy = calculate_cadence_entropy(operational_data['update_intervals'])
    
    # Normalize to [0, 1]
    timing_norm = timing_entropy / 4.58  # Max temporal entropy
    session_norm = session_entropy / 4.0   # Reasonable max
    cadence_norm = cadence_entropy / 3.32  # log₂(10) for 10-day window
    
    # Average normalized entropies
    score = (timing_norm + session_norm + cadence_norm) / 3
    
    return    score

# Interpretation
# score < 0.3: HIGH fingerprint risk (predictable)
# score 0.3-0.6: MEDIUM risk
# score > 0.6: LOW risk (high entropy)
```

---

## Defensive Optimization

### Goal
Maximize behavioral entropy to H > 3.5 bits per dimension.

### Technique: Controlled Randomization

```python
import random
from datetime import datetime, timedelta

class EntropyMaximizer:
    """Add controlled randomness to operations"""
    
    def randomized_activity_time(self, preferred_start=18, preferred_end=2):
        """Add ±4 hour jitter to preferred window"""
        base_hour = random.randint(preferred_start - 4, preferred_end + 4) % 24
        minute = random.randint(0, 59)
        return datetime.now().replace(hour=base_hour, minute=minute)
    
    def randomized_session_duration(self, min_hours=2, max_hours=8):
        """Random session length"""
        hours = random.uniform(min_hours, max_hours)
        return timedelta(hours=hours)
    
    def randomized_update_interval(self, min_days=3, max_days=10):
        """Random days until next update"""
        days = random.randint(min_days, max_days)
        return timedelta(days=days)

# Usage
optimizer = EntropyMaximizer()
next_activity = optimizer.randomized_activity_time()
session_length = optimizer.randomized_session_duration()
```

---

## Conclusion

**Measure**: Quantify current entropy  
**Target**: H > 3.5 bits per behavior  
**Optimize**: Add controlled randomness

**Key Insight**: Predictability is fingerprintability.

---

*உலகம் அறிவினால் மேம்படும்*

"The world progresses through knowledge."
