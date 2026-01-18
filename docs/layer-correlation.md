# Layer Correlation Analysis

## Purpose

This document provides **practical methodologies** for detecting OPSEC failures through cross-layer signal correlation.

Understanding *how* to correlate weak signals is the foundation of both:
- **Offensive OPSEC**: Identifying your own leaks before adversaries do
- **Defensive threat hunting**: Detecting adversaries through emergent patterns

---

## Correlation Theory

### Fundamental Principle

**Single weak signals are noise. Multiple correlated weak signals are attribution.**

```
Signal Strength = Individual_Signal_Strength × Correlation_Factor^(N-1)

Where:
- N = number of correlated signals
- Correlation_Factor = confidence that signals share common source (0.0-1.0)
```

**Example**:
- Signal A alone: 10% attribution confidence
- Signal B alone: 15% attribution confidence
- A + B correlated (0.8 confidence): ~70% attribution confidence
- A + B + C correlated (0.8 confidence each): ~95%+ attribution confidence

**Takeaway**: Exponential growth in attribution confidence with each correlated layer.

---

## Correlation Methodologies

### Method 1: Temporal Correlation

**Principle**: Events occurring within a narrow time window share causality.

#### DNS + Network Flow Correlation
```
Timeline:
T+0ms:    DNS query for "api.example.com" observed at resolver
T+50ms:   TLS connection to 203.0.113.42:443 observed in netflow
T+100ms:  HTTP request metadata (size patterns) observed

Correlation:
- Query timing + connection timing → same application
- DNS result (IP) matches connection destination
- Confidence: HIGH (>90%)
```

**Implementation**:
```python
def correlate_dns_network(dns_events, netflow_events, time_window_ms=500):
    correlations = []
    for dns_event in dns_events:
        dns_time = dns_event.timestamp
        dns_ip = dns_event.resolved_ip
        
        # Find network flows within time window to resolved IP
        for flow in netflow_events:
            if abs(flow.timestamp - dns_time) <= time_window_ms:
                if flow.dst_ip == dns_ip:
                    correlations.append({
                        'dns': dns_event,
                        'flow': flow,
                        'confidence': 1.0 - (abs(flow.timestamp - dns_time) / time_window_ms),
                        'type': 'DNS_NETWORK_TEMPORAL'
                    })
    return correlations
```

**OPSEC Countermeasure**:
- Pre-resolve DNS with random jitter
- Connection timing randomization
- Decoy traffic to break 1:1 correlation

---

#### Activity Timing + Timezone Correlation
```
Data Points:
- GitHub commits: Always 09:00-17:00 UTC
- Infrastructure updates: Always 19:30-03:30 UTC
- Difference: +10.5 hours

Analysis:
09:00 UTC = 19:00 Adelaide (UTC+10:30)
19:30 UTC = 06:00 Adelaide (next day)

Hypothesis: Operator in Adelaide timezone, work hours + evening operations

Confidence: MEDIUM-HIGH (multiple timezones fit, but narrow set)
```

**OPSEC Countermeasure**:
- Automated operations with randomized timing
- Multi-timezone operational diversity
- Time-delayed commits (batch and randomize)

---

### Method 2: Spatial/Geographic Correlation

**Principle**: Infrastructure components in the same geographic/network region share operational control.

####BGP AS-Path + DNS Resolver Correlation
```
Observable Signals:
- VPN exit: AS64512 (Sweden)
- DNS queries: Recursive resolver 8.8.8.8 (AS15169, Google, anycast)
- Anycast selection: Google resolver anycast node in Stockholm

Correlation:
- VPN exit in Sweden
- DNS anycast selects geographically close node (Stockholm)
- → Confirms VPN location, narrows true location to Northern Europe

Confidence: MEDIUM (anycast can be manipulated, but requires sophistication)
```

**Advanced Attack**:
```
Step 1: Probe DNS resolver latency to multiple IPs
Step 2: Triangulate based on RTT (round-trip time)
Step 3: Correlate with VPN exit AS
Step 4: Narrow to geographic region
```

**OPSEC Countermeasure**:
- Use DNS resolver in different geographic region than VPN exit
- Private recursive resolver (don't use anycast public resolvers)
- Accept latency cost for OPSEC

---

#### CDN Selection + Routing Correlation
```
Observable:
- User connects to Cloudflare edge: SJC (San Jose, CA)
- BGP path shows AS-path through Hurricane Electric (AS6939)
- User's local time artifacts: PST (UTC-8)

Correlation:
- Cloudflare anycast selects edge closest to user
- BGP path shows west coast US routing
- Timezone artifacts match California
- → High-confidence California localization

Confidence: HIGH
```

**OPSEC Countermeasure**:
- Avoid CDNs (they optimize for proximity, leak geolocation)
- If using CDN, use VPN/Tor to obfuscate true location
- Sanitize timezone artifacts

---

### Method 3: Infrastructural Linkage Correlation

**Principle**: Shared infrastructure components indicate common ownership.

#### SSL Certificate Clustering
```
Observable:
- Domain A: example1.com, SSL cert CN: *.example1.com, issuer: Let's Encrypt, serial: 0x1234...
- Domain B: example2.com, SSL cert CN: *.example2.com, issuer: Let's Encrypt, serial: 0x5678...
- Both certs: Same subject alternative names (SANs), same creation timestamp, sequential serial numbers

Correlation:
- Same certificate authority
- Certificates requested in batch (sequential serials)
- → Same operational infrastructure, likely same operator

Confidence: HIGH (if additional metadata matches)
```

**OPSEC Countermeasure**:
- Unique certificates per domain
- Distribute certificate creation across time
- Use different CAs for different operations

---

#### Hosting Infrastructure Clustering
```
Observable:
- Multiple domains resolve to IPs in same /24 subnet
- All IPs in same AS (e.g., AS12345 - BulletproofHostingCo)
- WHOIS registration: Privacy guard, same registrar, registered within same week

Correlation:
- IP co-location suggests shared hosting or operator
- AS reputation (bulletproof hosting) increases suspicion
- Temporal registration pattern indicates campaign setup

Confidence: MEDIUM-HIGH
```

**OPSEC Countermeasure**:
- Diverse hosting (different ASes, providers, geographic regions)
- Avoid IP clustering (use different subnets)
- Temporal distribution of domain registration

---

### Method 4: Behavioral Signature Correlation

**Principle**: Operational patterns are consistent across infrastructure.

#### C2 Beaconing Pattern Correlation
```
Observable:
- Malware A: Beacons every 3600s ± 180s (1 hour with 3-minute jitter)
- Malware B: Beacons every 3600s ± 180s
- Both: Use HTTP GET with specific User-Agent
- Both: Encode data in Cookie header

Correlation:
- Identical beaconing interval and jitter
- Same protocol patterns
- → Same malware family or shared development

Confidence: HIGH (distinct behavioral signature)
```

**OPSEC Countermeasure**:
- Randomize beaconing intervals per-implant
- Behavioral diversity across operations
- Avoid hardcoded patterns

---

#### Update/Operational Cadence Correlation
```
Observable Operation A:
- Infrastructure updates: Every Tuesday 02:00-04:00 UTC
- No weekend activity
- Holidays off (US federal holidays)

Observable Operation B:
- Infrastructure updates: Every Tuesday 02:00-04:00 UTC
- No weekend activity
- Holidays off (US federal holidays)

Correlation:
- Identical operational tempo
- → Same operator or organization with same operational procedures

Confidence: MEDIUM-HIGH (shared operational discipline indicates linkage)
```

**OPSEC Countermeasure**:
- Randomized operational schedules per-operation
- Automated updates with jitter
- Avoid organizational patterns

---

## Multi-Layer Correlation Attack Chains

### Attack Chain 1: **Full Attribution via 4-Layer Correlation**

#### Layer 1: Userland (TLS Fingerprint)
```
Observable: JA3 hash = abc123... (matches specific curl version)
Confidence: LOW (many users use curl)
```

#### Layer 2: DNS (Resolver + Query Pattern)
```
Observable:
- Queries via 8.8.8.8
- Query pattern: Always A+AAAA in same request
- Specific domain typo pattern in queries
Confidence: LOW-MEDIUM (query pattern slightly unusual)
```

#### Layer 3: Network (AS-Path + Timing)
```
Observable:
- Traffic exits via AS64512 (specific VPN provider)
- BGP path shows European routing
- Connection timing: Consistent daily pattern
Confidence: MEDIUM (VPN provider narrows user set)
```

#### Layer 4: Metadata (Temporal)
```
Observable:
- All activity 18:00-02:00 UTC (consistent daily)
- No weekend activity
- GitHub commits from account "user123": Same time window
Confidence: LOW-MEDIUM alone
```

#### Correlation
```
curl version (Layer 1)
  + DNS resolver pattern (Layer 2)
  + VPN AS (Layer 3)
  + Activity window (Layer 4)
  + GitHub account timing match (Layer 4)
  = VERY HIGH confidence attribution

Final assessment:
- Operator likely "user123" on GitHub
- Located in UTC+1 or UTC+2 timezone (18:00 UTC = evening local time)
- Uses specific curl version → Linux/BSD environment
- Weekday operations → likely professional, not automated
```

**Result**: 4 weak signals → high-confidence human attribution

---

### Attack Chain 2: **DNS Sinkhole → Infrastructure Mapping**

#### Step 1: Sinkhole Hit Detection
```
Observable:
- Malware sample queries "malicious-example[.]com"
- Domain is sinkholed by threat intel feed
- Passive DNS shows queries from IP 203.0.113.42
```

#### Step 2: Passive DNS Pivot
```
Query passive DNS for 203.0.113.42:
- Also queries: infrastructure-domain1.com, infrastructure-domain2.com, ...
- All domains: Same hosting provider, registered same week
- → Infrastructure mapping via pivot
```

#### Step 3: AS/Hosting Correlation
```
All domains resolve to IPs in AS12345 "ShadyHosting Inc."
- AS has reputation score: High-risk
- → Increases confidence this is adversary infrastructure
```

#### Step 4: Temporal Correlation
```
Domain registration dates: 2024-03-01 to 2024-03-07
Campaign first observed: 2024-03-08
- → Correlation: Domains registered in preparation for campaign
```

#### Final Correlation
```
Sinkhole hit + Passive DNS pivot + AS reputation + Temporal pattern
= HIGH confidence full infrastructure enumeration

Actionable intelligence:
- Block all domains in cluster
- Monitor AS12345 for new registrations
- Track registrar for future domain registrations
```

---

### Attack Chain 3: **Routing Asymmetry → Geolocation**

#### Observable 1: Inbound Path
```
Traceroute to target from external vantage point:
1. ISP_A (AS1000)
2. IX_Frankfurt (AS2000)
3. Hurricane Electric (AS6939)
4. Target (AS64512)

Inbound path: USA → Frankfurt → Target
```

#### Observable 2: Outbound Path (from target)
```
BGP path from target to external endpoint:
AS64512 → AS7018 (AT&T) → AS3356 (Level3) → Destination

Outbound path: Target → USA carriers → Destination
```

#### Correlation
```
Asymmetry analysis:
- Inbound: Routes through Frankfurt IX
- Outbound: Routes through USA carriers
- → Target likely uses European VPN exit, but originates from USA
- → Routing asymmetry exposes true location

Geographic localization:
- True location: USA (outbound path preference)
- VPN exit: Europe (inbound path)
```

**OPSEC Insight**: Routing asymmetry defeats VPN geolocation obfuscation.

---

## Correlation Detection Tools & Techniques

### Tool 1: Temporal Correlation Matrix

**Purpose**: Detect time-based patterns across operations.

```python
import numpy as np
from scipy.stats import pearsonr

def temporal_correlation_matrix(operations_timeseries):
    """
    operations_timeseries: dict of {operation_id: [timestamps]}
    Returns: correlation matrix showing temporal overlap
    """
    op_ids = list(operations_timeseries.keys())
    n = len(op_ids)
    correlation_matrix = np.zeros((n, n))
    
    for i, op1 in enumerate(op_ids):
        for j, op2 in enumerate(op_ids):
            if i == j:
                correlation_matrix[i][j] = 1.0
            else:
                # Convert timestamps to hourly buckets
                hours1 = [t.hour for t in operations_timeseries[op1]]
                hours2 = [t.hour for t in operations_timeseries[op2]]
                
                # Calculate overlap
                hist1 = np.histogram(hours1, bins=24, range=(0, 24))[0]
                hist2 = np.histogram(hours2, bins=24, range=(0, 24))[0]
                
                # Pearson correlation
                corr, _ = pearsonr(hist1, hist2)
                correlation_matrix[i][j] = max(0, corr)
    
    return correlation_matrix, op_ids
```

**Usage**: Identify operations with similar time patterns → likely same operator.

---

### Tool 2: Infrastructure Graph Analysis

**Purpose**: Link infrastructure via shared attributes.

```python
import networkx as nx

def build_infrastructure_graph(domains_metadata):
    """
    domains_metadata: list of dicts with {domain, ip, as, ssl_cert_hash, registrar, ...}
    Returns: NetworkX graph with domains as nodes, shared attributes as edges
    """
    G = nx.Graph()
    
    for domain_data in domains_metadata:
        G.add_node(domain_data['domain'], **domain_data)
    
    # Link domains with shared attributes
    for i, d1 in enumerate(domains_metadata):
        for d2 in domains_metadata[i+1:]:
            edge_weight = 0
            shared_attrs = []
            
            # Same IP subnet (/24)
            if same_subnet(d1['ip'], d2['ip'], 24):
                edge_weight += 0.3
                shared_attrs.append('ip_subnet')
            
            # Same AS
            if d1['as'] == d2['as']:
                edge_weight += 0.2
                shared_attrs.append('as')
            
            # Same SSL cert (or similar)
            if d1.get('ssl_cert_hash') == d2.get('ssl_cert_hash'):
                edge_weight += 0.5
                shared_attrs.append('ssl_cert')
            
            # Same registrar + registration time window
            if d1['registrar'] == d2['registrar']:
                if abs(d1['registered_date'] - d2['registered_date']).days < 7:
                    edge_weight += 0.4
                    shared_attrs.append('registrar_temporal')
            
            if edge_weight > 0:
                G.add_edge(d1['domain'], d2['domain'], 
                          weight=edge_weight,
                          shared_attributes=shared_attrs)
    
    return G

def find_infrastructure_clusters(graph, min_weight=0.5):
    """Find connected components with strong linkages"""
    # Filter edges by weight
    strong_graph = nx.Graph()
    for u, v, data in graph.edges(data=True):
        if data['weight'] >= min_weight:
            strong_graph.add_edge(u, v, **data)
    
    # Find connected components
    clusters = list(nx.connected_components(strong_graph))
    return clusters
```

**Usage**: Identify domain clusters → map adversary infrastructure.

---

### Tool 3: Behavioral Similarity Scoring

**Purpose**: Quantify behavioral pattern similarity.

```python
from scipy.spatial.distance import euclidean

def behavioral_signature(operation_data):
    """Extract behavioral features"""
    return {
        'avg_session_duration': np.mean(operation_data['session_durations']),
        'session_count_per_day': len(operation_data['sessions']) / operation_data['days_observed'],
        'hour_of_day_entropy': calculate_entropy(operation_data['activity_hours']),
        'weekend_activity_ratio': operation_data['weekend_sessions'] / len(operation_data['sessions']),
        'update_frequency_days': np.mean(operation_data['update_intervals']),
        # ... more behavioral features
    }

def behavioral_similarity(sig1, sig2):
    """Compute similarity score between two behavioral signatures"""
    features1 = np.array(list(sig1.values()))
    features2 = np.array(list(sig2.values()))
    
    # Normalize features
    features1_norm = (features1 - features1.mean()) / (features1.std() + 1e-10)
    features2_norm = (features2 - features2.mean()) / (features2.std() + 1e-10)
    
    # Euclidean distance (lower = more similar)
    distance = euclidean(features1_norm, features2_norm)
    
    # Convert to similarity score (0.0 - 1.0)
    similarity = 1.0 / (1.0 + distance)
    return similarity
```

**Usage**: Find operations with similar behavior → same operator/team.

---

## OPSEC Audit Methodology

### Step 1: Enumerate Your Signals
For each layer, list what signals you emit:
```
| Layer | Signal | Observability | Uniqueness |
|-------|--------|--------------|------------|
| L-USER | TLS fingerprint | High | Medium |
| L-DNS | Resolver IP | High | Low |
| L-NET | VPN AS | High | Medium |
| L-META | Activity 18:00-02:00 UTC | High | Medium |
```

### Step 2: Identify Correlation Pairs
Which 2-3 signals, if correlated, would defeat OPSEC?
```
High-risk pairs:
- VPN AS + DNS resolver AS mismatch
- Activity timing + GitHub commit timing
- TLS fingerprint + known tool version
```

### Step 3: Estimate Detection Probability
For each adversary tier:
```
Tier 1: Can they observe these signals? Can they correlate?
Tier 2: Manual analysis → how unique is your signal combination?
Tier 3: Historical data → how much does correlation reveal over time?
```

### Step 4: Prioritize Mitigations
Focus on **high-correlation, high-uniqueness** signals:
1. Break unique signature combinations first
2. Add noise/diversity to reduce correlation confidence
3. Accept low-correlation risks

### Step 5: Continuous Monitoring
Track your own infrastructure as an adversary would:
- Monitor passive DNS for your domains
- Check threat intel feeds for your IPs
- Audit BGP announcements
- Review temporal patterns

---

## Defensive Applications (Threat Hunting)

### Hunt 1: DNS + Network Flow Temporal Correlation

**Objective**: Detect malware C2 beaconing via correlated DNS+network.

```
Query: Find DNS queries followed by network flows to resolved IP within 500ms
Filter: Exclude known-good domains (whitelist)
Alert: Repeated pattern → potential C2
```

### Hunt 2: Infrastructure Clustering

**Objective**: Map adversary infrastructure via shared attributes.

```
Data sources: Passive DNS, SSL cert database, WHOIS
Method: Graph analysis (shared IPs, certs, registrars)
Output: Cluster of related domains → threat actor infrastructure
```

### Hunt 3: Behavioral Outlier Detection

**Objective**: Identify unusual operational timing.

```
Baseline: Normal activity hours for legitimate users/systems
Outlier: Activity consistently at unusual hours (02:00-05:00 local time)
Investigation: Potential adversary operating in different timezone
```

---

## Key Takeaways

1. **Correlation is exponential** — Each additional signal dramatically increases confidence
2. **Temporal correlation is underestimated** — Time is a powerful correlator
3. **Infrastructure linkage is trivial** — Shared attributes (IPs, certs, AS) expose relationships
4. **Behavioral patterns are persistent** — Human habits leak through timing
5. **No single mitigation suffices** — Must break correlation across ALL layers

---

*यस्य कार्ये न जानाति तेन तत्र न गम्यते।*

"One who does not understand the work should not undertake it."

**If you cannot enumerate your correlation risks, you cannot defend against them.**
