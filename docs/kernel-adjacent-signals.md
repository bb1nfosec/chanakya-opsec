# Kernel-Adjacent Observable Signals

## Overview

Kernel-adjacent signals are observable side-effects of kernel and low-level system behavior that leak operational security information **without requiring kernel modules or root access**.

These signals sit at the boundary between userland and kernel—they're accessible via standard system calls but reveal low-level patterns that fingerprint:
- Workload types (crypto vs. network I/O vs. database)
- System configuration
- Operational tempo
- Infrastructure purpose

**Key Insight**: You don't need to compromise the kernel to observe kernel-level patterns.

---

## Signal Categories

### 1. **Syscall Timing Side-Channels**

#### Concept
Different workloads produce different syscall latency distributions. ML can classify workload types from timing alone.

#### Observable Signals

| Workload Type | Syscall Pattern | Timing Signature |
|---------------|----------------|------------------|
| **Crypto Mining** | Massive `read()` from `/dev/urandom`, high CPU | Long CPU-bound intervals |
| **Web Server** | Frequent `accept()`, `read()`, `write()` | Short, bursty network I/O |
| **Database** | Heavy `fsync()`, `pread()`/`pwrite()` | Disk I/O latency dominant |
| **C2 Server** | Periodic `select()`/`poll()`, low volume | Predictable timing intervals |

#### Attribution Potential
- **Visibility**: MODERATE (requires process monitoring or eBPF without root via USDT probes)
- **Correlation**: MEDIUM (workload fingerprint correlates with infrastructure purpose)
- **Mitigation Difficulty**: HIGH (fundamentally tied to operational purpose)

---

### 2. **Scheduler Behavior Leaks**

#### Concept
The Linux CFS (Completely Fair Scheduler) makes decisions based on workload. These decisions are observable via `/proc/[pid]/sched`.

#### Observable Metrics
```bash
# Accessible without root for owned processes
cat /proc/self/sched

nr_voluntary_switches: 1523   # Workload voluntarily yields (I/O bound)
nr_involuntary_switches: 47   # Preempted by scheduler (CPU bound)
```

**Analysis:**
```
High voluntary / Low involuntary → I/O-bound (network, disk)
Low voluntary / High involuntary → CPU-bound (crypto, computation)
```

#### Fingerprinting Attack
```python
def classify_workload_from_scheduler(pid):
    sched_stats = parse_proc_sched(pid)
    voluntary = sched_stats['nr_voluntary_switches']
    involuntary = sched_stats['nr_involuntary_switches']
    
    ratio = voluntary / max(1, involuntary)
    
    if ratio > 10:
        return "I/O-bound (likely network/web service)"
    elif ratio < 2:
        return "CPU-bound (likely crypto/computation)"
    else:
        return "Mixed workload"
```

---

### 3. **Memory Access Patterns**

#### Concept
Even without Spectre/Meltdown, memory access patterns leak through:
- Page faults (`/proc/[pid]/stat` field 12, 10)
- Memory maps (`/proc/[pid]/maps`)
- Resident set size changes

#### Observable Signals

| Pattern | Indicator | Workload Inference |
|---------|-----------|-------------------|
| **High minor page faults** | Frequent new allocations | Dynamic memory (scripting languages, JIT) |
| **Stable RSS** | Few page faults | Static binary (compiled C/C++) |
| **Large anonymous mappings** | Big `[heap]` or `[stack]` | In-memory databases, caches |
| **Many `mmap()` calls** | Fragmented maps | JVM, V8, dynamic libs |

#### Fingerprint Value
- JVM/Node.js processes have characteristic memory maps
- Static Go binaries have minimal dynamic allocations
- Python/Ruby show interpreter memory patterns

---

### 4. **Interrupt Timing**

#### Concept
Hardware interrupts (network, disk) create timing patterns visible in `/proc/interrupts`.

**Without root**: Can observe interrupt rates for network interfaces (if process has access).

**With root** (or via sidechannels): Full interrupt timing analysis.

#### Attack Vector
```
High network interrupt rate + low syscall rate = 
    → Likely packet inspection/filtering device
    
High disk interrupts + periodic pattern =
    → Likely backup/logging infrastructure
```

---

### 5. **Entropy Source Analysis**

#### Concept
`/dev/urandom` and `/dev/random` have observable characteristics:
- Read frequency
- Bytes requested per read
- Timing between reads

#### OPSEC Leak
```python
# Crypto operations need randomness
Frequent reads from /dev/urandom (100+ per second)
Consistent read sizes (16, 32, 64 bytes)

→ Likely crypto key generation or nonce generation
→ Infers crypto infrastructure
```

#### Strace Example
```bash
$ strace -e open,read -p [pid] 2>&1 | grep urandom
read(3, "\x37\xf2...", 32) = 32  # /dev/urandom
read(3, "\x8a\x1c...", 32) = 32
read(3, "\xb4\x5e...", 32) = 32
# Consistent 32-byte reads → AES-256 key stream likely
```

---

## Quantitative Analysis Framework

###  Syscall Entropy

**Metric**: Shannon entropy of syscall distribution

```python
import math
from collections import Counter

def syscall_entropy(syscall_trace):
    """
    Calculate Shannon entropy of syscall distribution
    Higher entropy = more diverse workload
    Lower entropy = specialized/predictable workload
    """
    counts = Counter(syscall_trace)
    total = len(syscall_trace)
    
    entropy = 0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    
    return entropy

# Example
web_server_calls = ['accept', 'read', 'write', 'close'] * 100  # Repetitive
crypto_miner_calls = ['read'] * 300 + ['write'] * 50  # Very low variety

web_entropy = syscall_entropy(web_server_calls)   # ≈ 2.0 bits
crypto_entropy = syscall_entropy(crypto_miner_calls)  # ≈ 0.76 bits

# Lower entropy → more predictable → easier to fingerprint
```

---

### Timing Distribution Analysis

**Metric**: KL-Divergence between observed and expected latency distributions

```python
import numpy as np
from scipy.stats import entropy

def kl_divergence_timing(observed_latencies, baseline_latencies):
    """
    Calculate KL-divergence between observed and baseline timing
    High divergence → anomalous workload
    """
    # Create histograms
    obs_hist, _ = np.histogram(observed_latencies, bins=50, density=True)
    base_hist, _ = np.histogram(baseline_latencies, bins=50, density=True)
    
    # Add small epsilon to avoid log(0)
    obs_hist += 1e-10
    base_hist += 1e-10
    
    return entropy(obs_hist, base_hist)

# High KL-divergence → workload differs from baseline
# → Enables workload classification
```

---

## Machine Learning Workload Classification

### Training Data

Collect syscall traces from known workloads:
- Web servers (nginx, apache)
- Databases (postgres, mysql)
- Crypto miners (xmrstack, ethminer)
- C2 frameworks (Metasploit, Cobalt Strike)

### Feature Extraction

```python
features = [
    'accept_frequency',       # Network server indicator
    'read_write_ratio',       # I/O pattern
    'fsync_count',            # Database indicator
    'urandom_read_freq',      # Crypto indicator
    'voluntary_ctx_switches', # Scheduler signature
    'syscall_entropy',        # Diversity metric
    'mean_syscall_latency',   # Timing signature
    'memory_page_faults',     # Memory pattern
]
```

### Classification Model

```python
from sklearn.ensemble import RandomForestClassifier

# Train on labeled data
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_labels)  # Labels: "web", "database", "crypto", "c2"

# Classify unknown process
unknown_features = extract_features(unknown_pid)
prediction = model.predict([unknown_features])
confidence = model.predict_proba([unknown_features]).max()

print(f"Workload: {prediction[0]} (confidence: {confidence:.2%})")
```

**Real-World Accuracy**: 80-90% for clean processes, 60-75% with obfuscation

---

## Defensive Techniques

### 1. **Workload Diversity**

Add noise to syscall patterns:
```c
// Bad: Predictable pattern
while (1) {
    read(fd, buf, 1024);
    process(buf);
}

// Better: Add timing jitter
while (1) {
    read(fd, buf, 1024);
    usleep(rand() % 10000);  // Random 0-10ms delay
    process(buf);
}
```

### 2. **Syscall Obfuscation**

Insert dummy syscalls to increase entropy:
```c
// Periodically make random syscalls that do nothing
void noise_syscalls() {
    int dummy_fd = open("/dev/null", O_RDONLY);
    read(dummy_fd, buf, rand() % 100);
    close(dummy_fd);
}
```

**Warning**: Detectable via statistical analysis, but raises classification cost.

### 3. **Process Isolation**

Run different operational functions in separate containers/VMs:
- C2 communication in one process
- Keylogging in another
- Crypto operations in a third

→ Each process has ambiguous/generic fingerprint

### 4. **Rate Limiting**

Throttle operations to avoid distinctive patterns:
```python
# Bad: Burst 1000 crypto operations
for i in range(1000):
    generate_key()

# Better: Rate-limited to blend in
for i in range(1000):
    generate_key()
    time.sleep(random.uniform(0.1, 2.0))  # Looks like normal workload
```

---

## Integration with CHANAKYA Framework

### New Analyzer Module

```python
# framework/kernel/syscall_analyzer.py

from framework import Signal, OpsecLayer, OpsecAnalyzer
import subprocess
import re

class SyscallAnalyzer(OpsecAnalyzer):
    """Analyze syscall patterns for workload fingerprinting"""
    
    def analyze(self, pid):
        """Run strace and analyze syscall patterns"""
        # Run strace for limited time
        strace_output = subprocess.check_output(
            ['strace', '-c', '-p', str(pid), '-e', 'trace=all'],
            timeout=10,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        signals = []
        
        # Parse syscall distribution
        syscalls = self._parse_strace_output(strace_output)
        entropy = self._calculate_entropy(syscalls)
        
        # Low entropy = predictable workload
        if entropy < 2.0:
            signals.append(Signal(
                signal_id="low_syscall_entropy",
                layer=OpsecLayer.USERLAND,
                description=f"Low syscall entropy detected: {entropy:.2f} bits",
                value=f"{entropy:.2f}",
                correlation_potential="MULTI",
                detectability="MODERATE",
                metadata={'entropy': entropy, 'risk': 'Predictable workload fingerprint'}
            ))
        
        # Detect crypto pattern
        if self._is_crypto_pattern(syscalls):
            signals.append(Signal(
                signal_id="crypto_syscall_pattern",
                layer=OpsecLayer.USERLAND,
                description="Syscall pattern indicates crypto operations",
                value="High /dev/urandom reads",
                correlation_potential="PAIR",
                detectability="HIGH",
                metadata={'pattern': 'crypto', 'risk': 'Infrastructure purpose revealed'}
            ))
        
        return signals
```

---

## Attribution Weight

Using the quantitative scoring framework:

| Signal | V (T2) | V (T3) | R | C | **AW (T3)** | Risk |
|--------|--------|--------|---|---|------------|------|
| Syscall pattern → crypto workload | 0.3 | 0.7 | 0.6 | 0.6 | **0.25** | MEDIUM |
| Low syscall entropy | 0.2 | 0.6 | 0.5 | 0.5 | **0.15** | LOW |
| Scheduler: CPU-bound | 0.25 | 0.65 | 0.55 | 0.5 | **0.18** | LOW |
| High `/dev/urandom` reads | 0.35 | 0.75 | 0.7 | 0.65 | **0.34** | MEDIUM |

**Composite Risk** (all signals present): 0.68 → **HIGH**

---

## Conclusion

Kernel-adjacent signals provide **infrastructure purpose attribution** without kernel access:
- Workload classification (crypto, web, database, C2)
- Operational tempo fingerprinting
- System configuration leaks

**Defensive Difficulty**: HIGH  
Workload patterns are tied to operational purpose—hard to randomize without breaking functionality.

**Mitigation Strategy**: Isolation + noise injection + rate limiting

---

*கற்றது க Tamil wisdom translated*

"What is learned is a handful; what is yet to be learned is the size of the world."

**The kernel remembers. Choose your patterns wisely.**
