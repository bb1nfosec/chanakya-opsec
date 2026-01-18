# OSINT Correlation & Attribution Techniques

## Overview

Open Source Intelligence (OSINT) leverages publicly available information to attribute operations. In 2026, the volume of public data makes OSINT one of the **most powerful attribution vectors**.

**Key Insight**: Your public digital footprint is permanent and correlatable.

---

## GitHub/Code Repository Intelligence

### Commit Timing Correlation

**Attack Vector**: Correlate commit times with operational activity.

**Collection**:
```python
import requests
from datetime import datetime

def get_commit_times(username):
    url = f"https://api.github.com/users/{username}/events/public"
    events = requests.get(url).json()
    
    commit_times = []
    for event in events:
        if event['type'] == 'PushEvent':
            timestamp = datetime.fromisoformat(event['created_at'].replace('Z', '+00:00'))
            commit_times.append(timestamp.hour)
    
    return commit_times

# Statistical correlation with operational timing
def correlate_timing(commit_hours, operational_hours):
    from scipy.stats import pearsonr
    r, p_value = pearsonr(commit_hours, operational_hours)
    
    if r > 0.7 and p_value < 0.05:
        return "HIGH CONFIDENCE: Same operator"
    elif r > 0.5:
        return "MEDIUM CONFIDENCE: Likely related"
    else:
        return "LOW CONFIDENCE"
```

**Attribution Weight**: V=1.0, R=1.0, C=0.9 → **AW=0.90 (CRITICAL)**

---

### Code Style Attribution (Stylometry)

**Technique**: Machine learning on coding patterns (variable names, comments, structure).

**Accuracy**: 80-95% for known developers with sufficient samples.

**Features**:
- Variable naming conventions (`camelCase` vs. `snake_case`)
- Comment density and style
- Function length preferences
- Import statement ordering
- Error handling patterns

**Example**:
```python
# Developer A signature
def processData(inputString):  # camelCase
    return inputString.upper()  # No comments, concise

# Developer B signature
def process_user_input(input_str):  # snake_case
    """Process and sanitize user input"""  # Docstrings
    # Input validation
    if not input_str:
        raise ValueError("Empty input")
    return input_str.upper()
```

**Attribution Weight**: V=0.8, R=1.0, C=0.75 → **AW=0.60 (HIGH)**

---

### Email Leaks in Git History

**Attack Vector**: Old commits may contain email addresses even if later changed.

**Collection**:
```bash
git log --all --format='%aE' | sort -u
# Lists all emails ever used in repository
```

**Common Leak**:
```
Commit 1-50: developer@personal-email.com
Commit 51+: anon@protonmail.com

→ Links anonymous identity to real identity
```

**Attribution Weight**: V=0.9, R=1.0, C=1.0 → **AW=0.90 (CRITICAL)**

---

## LinkedIn & Professional Networks

### Team Structure Inference

**Intelligence Value**:
- Job postings reveal capabilities being built
- New hires' backgrounds reveal project direction
- Simultaneous hiring spikes indicate new initiatives

**Example Chain**:
```
1. Company X posts: "Seeking Python security researcher"
2. 3 months later: 5 LinkedIn profiles update to "Security Researcher at Company X"
3. GitHub: New org "CompanyX-Security" created
4. Inference: Company X building offensive security team
```

**Attribution Weight**: V=0.9, R=0.95, C=0.8 → **AW=0.68 (HIGH)**

---

### Conference Attendance Tracking

**Data Sources**:
- Conference attendee Facebook groups
- Twitter posts with conference hashtags
- Badge photos (CRITICAL - reveals real name)
- Conference Wi-Fi logs (if accessible)

**Attack Chain**:
```
1. Twitter: "Excited for #DefCon2024!"
2. Photo posted: Badge visible with real name
3. Photo EXIF: GPS coordinates in Las Vegas
4. Background: Other attendees visible → identify team
5. LinkedIn: Real name → full professional history
```

**Attribution Weight**: V=0.95, R=1.0, C=0.95 → **AW=0.90 (CRITICAL)**

---

## Domain WHOIS & Infrastructure

### WHOIS Correlation

**Technique**: Historical WHOIS data links infrastructure.

**Example**:
```
Domain A: operations@example.com (registered 2024-01-15)
Domain B: operations@example.com (registered 2024-01-17)
Domain C: operations@example.com (registered 2024-01-16)

→ Same email, 72-hour window → Likely same campaign
```

**Passive DNS + WHOIS Fusion**:
```
Domains A, B, C all resolve to IPs in same /24
Same registrant email
Same nameservers (ns1.provider.com)

→ HIGH CONFIDENCE infrastructure cluster
```

**Attribution Weight**: V=0.9, R=1.0, C=0.95 → **AW=0.86 (CRITICAL)**

---

## Social Media Timing Analysis

### Cross-Platform Temporal Correlation

**Data Collection**:
```python
def collect_activity_times(platforms):
    """
    platforms = {
        'twitter': @username,
        'github': username,
        'reddit': u/username,
        'linkedin': profile_id
    }
    """
    activity_times = {}
    
    for platform, account in platforms.items():
        times = scrape_activity_times(platform, account)
        activity_times[platform] = times
    
    # Correlate timing across platforms
    correlation_matrix = calculate_cross_platform_correlation(activity_times)
    
    return correlation_matrix

# If correlation > 0.7 across platforms → Likely same person
```

**Attribution Weight**: V=0.8, R=0.9, C=0.85 → **AW=0.61 (HIGH)**

---

## Geolocation from Photos

### EXIF Metadata Extraction

**Attack Vector**: Social media photos contain GPS coordinates.

**Tool**:
```bash
exiftool conference_selfie.jpg | grep GPS
# Output:
# GPS Position: 36°10'30.0"N 115°08'11.0"W
# → Las Vegas Convention Center
```

**Cross-INT with GEOINT**:
```
EXIF GPS → Lat/Long → Google Maps → Specific building
Conference badge in photo → Real name revealed
```

**Attribution Weight**: V=0.9, R=1.0, C=0.9 → **AW=0.81 (CRITICAL)**

---

## Job Posting Analysis

### Capability Inference

**Intelligence Collection**:
```
Job Posting Keywords → Capabilities Being Built

"Experience with Cobalt Strike" → Offensive capability
"Tor network expertise" → Anonymity research
"Linux kernel development" → Low-level capability
"Python + network protocols" → Tooling development
```

**Timeline Analysis**:
```
Month 0: Job posted
Month 3: Position filled (LinkedIn)
Month 6-12: Likely capability operational
```

**Attribution Weight**: V=0.7, R=0.8, C=0.6 → **AW=0.34 (MEDIUM)**

---

## Cross-INT OSINT Correlations

### OSINT + GEOINT + HUMINT Fusion

**Multi-INT Attack Chain**:
```
1. OSINT (GitHub): Commits 18:00-02:00 UTC, timezone clues in code
2. GEOINT (IP): Geolocation shows Stockholm
3. OSINT (LinkedIn): Profile lists location as Stockholm
4. HUMINT (Conference): Badge photo from Stockholm tech event
5. OSINT (Social): Facebook check-in at Stockholm co-working space
6. GEOINT (Satellite): Identify specific building

Result: FULL ATTRIBUTION with location down to building level
```

---

## Defensive Techniques

### 1. Separate Identities
- **Never** link operational accounts to personal accounts
- Different email domains
- Different coding styles
- Different activity times

### 2. Scrub Git History
```bash
# Remove email from all commits
git filter-branch --env-filter '
export GIT_AUTHOR_EMAIL="anon@domain.com"
export GIT_COMMITTER_EMAIL="anon@domain.com"
' --all
```

### 3. Avoid Public Photos
- No conference badge selfies
- No location tags on social media
- Strip EXIF before posting photos

### 4. Timing Diversity
- Don't commit to GitHub during operational hours
- Randomize activity timing
- Use scheduled commits (not real-time)

---

## Quantitative Risk Assessment

| OSINT Signal | V | R | C | **AW** | Risk |
|--------------|---|---|---|--------|------|
| GitHub commit timing | 1.0 | 1.0 | 0.9 | **0.90** | CRITICAL |
| Email in git history | 0.9 | 1.0 | 1.0 | **0.90** | CRITICAL |
| Conference badge photo | 0.95 | 1.0 | 0.95 | **0.90** | CRITICAL |
| WHOIS correlation | 0.9 | 1.0 | 0.95 | **0.86** | CRITICAL |
| Photo EXIF GPS | 0.9 | 1.0 | 0.9 | **0.81** | CRITICAL |
| LinkedIn team inference | 0.9 | 0.95 | 0.8 | **0.68** | HIGH |
| Social media timing | 0.8 | 0.9 | 0.85 | **0.61** | HIGH |
| Code stylometry | 0.8 | 1.0 | 0.75 | **0.60** | HIGH |

**Composite OSINT Risk**: 0.99 → **CRITICAL**

---

## Conclusion

**OSINT is the most accessible and highest-yield attribution vector in 2026.**

**Critical truths**:
1. Public data is permanent (GitHub, LinkedIn, WHOIS)
2. Timing patterns leak across platforms
3. Photos leak location via EXIF
4. Conference attendance is identity revelation
5. No amount of technical OPSEC fixes poor tradecraft

**Defense**: Ruthless compartmentalization. Zero linkage between identities.

---

*அறிவே கடவுள்*

"Knowledge is divine."

**The public knows more than you think. Act accordingly.**
