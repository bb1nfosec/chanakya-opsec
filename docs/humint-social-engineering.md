# HUMINT Social Engineering & Behavioral Attribution

## Overview

Human Intelligence (HUMINT) targets the **human element**: behavioral patterns, social connections, and psychological profiles.

**Key Insight**: Humans are the weakest link. Patterns persist.

---

## Behavioral Timing Analysis

### Work-Life Pattern Recognition

**Signals**:
```
Operations: 18:00-02:00 UTC, Monday-Friday only
Inference:
- Full-time employment elsewhere (daytime)
- Evening hobby/side project
- Geographic: UTC+1/+2 (18:00 UTC = 19:00-20:00 local)
```

**Attribution Weight**: V=0.7, R=0.8, C=0.85 → **AW=0.48 (MEDIUM-HIGH)**

---

## Language & Cultural Indicators

**Code Analysis**:
```python
# European date format assumption
date_format = "DD/MM/YYYY"  # Not MM/DD/YYYY (US)

# Comment style
# Uses British spelling: "colour" not "color"

→ Likely European developer
```

**Attribution Weight**: V=0.5, R=0.6, C=0.55 → **AW=0.17 (LOW)**

---

## Conference Attendance (Physical OPSEC Failure)

**Attack Vector**: Badge photos leak identity.

**Data Leaked**:
- Real name
- Company
- GPS coordinates (EXIF)
- Other attendees (background)

**Attribution Weight**: V=0.95, R=1.0, C=0.95 → **AW=0.90 (CRITICAL)**

---

## Social Engineering Attack Surface

**Vectors**:
- LinkedIn team structure
- Personal life (family, hobbies)
- Financial stress
- Ideological motivations

**OPSEC Impact**: HUMINT enables targeted social engineering attacks.

---

*மனிதர்கள் முக்கியம்*

"Humans are key."

**Technology can be perfect. Humans never are.**
