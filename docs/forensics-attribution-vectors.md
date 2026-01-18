# Digital Forensics & OPSEC Failure Analysis

## Overview

Digital forensics reveals OPSEC failures through **artifact analysis, timeline reconstruction, and evidence correlation**. This document covers forensic techniques that expose operational security weaknesses.

**Key Insight**: Digital evidence persists far longer than operators expect.

---

## Filesystem Forensics

### File Timestamps (MAC Times)

**Attack Vector**: Metadata timestamps reveal activity patterns.

**MAC Times:**
- **M**odified: Content changed
- **A**ccessed: File read
- **C**hanged: Metadata changed (permissions, ownership)

**OPSEC Failure Example**:
```bash
# Operator creates malware
touch malware.py  # Created: 2024-03-15 18:30 UTC

# Modifies it
echo "payload" >> malware.py  # Modified: 2024-03-15 19:45 UTC

# Forensic analysis
stat malware.py
# Created: 2024-03-15 18:30 → Timezone inference (evening hours)
# Modified: 2024-03-15 19:45 → 75-minute development window
```

**Attribution Weight**: V=0.7, R=0.9, C=0.7 → **AW=0.44 (MEDIUM)**

---

### Deleted File Recovery

**Technique**: Files are not truly deleted until overwritten.

**Tools**:
- `photorec`, `testdisk` (undelete tools)
- `foremost` (carve deleted files from disk)

**OPSEC Failure**:
```
Operator deletes: operational_notes.txt
Forensics recovers: Full operational plan with timelines

Defense: Secure deletion (shred -vfz -n 7 file)
```

**Attribution Weight**: V=0.6, R=0.8, C=0.8 → **AW=0.38 (MEDIUM)**

---

### Thumbnail Cache

**Attack Vector**: OS caches thumbnails of images even after deletion.

**Windows**: `Thumbs.db`, `thumbcache_*.db`  
**Linux**: `~/.cache/thumbnails/`  
**Mac**: `~/.Trash/`

**OPSEC Failure**:
```
Operator views: target_location_map.jpg
Deletes: target_location_map.jpg
Thumbnail persists in cache → Forensics recovers image
```

**Attribution Weight**: V=0.5, R=0.7, C=0.6 → **AW=0.21 (LOW)**

---

## Memory Forensics

### RAM Artifacts

**Attack Vector**: Memory dumps contain cleartext secrets.

**Recoverable Data**:
- Cleartext passwords (even if encrypted on disk)
- Encryption keys
- Command history
- Network connections
- Running process memory

**Tools**: Volatility, Rekall

**Example**:
```bash
volatility -f memory.raw --profile=Win10x64 cmdline
# Output: Full command history including passwords in commands
```

**Attribution Weight**: V=0.4, R=0.3, C=0.7 → **AW=0.08 (LOW - requires RAM access)**

---

## Browser Forensics

### Browser History

**Persistence**: Even "private/incognito" mode leaves traces.

**Artifacts**:
- SQLite databases (`places.sqlite` in Firefox)
- Cache files
- DNS cache (resolves even if history cleared)
- Autocomplete data

**OPSEC Failure**:
```sql
-- Firefox places.sqlite
SELECT url, visit_date FROM moz_places ORDER BY visit_date DESC;

-- Results show operational reconnaissance sites even if "private browsing"
```

**Attribution Weight**: V=0.7, R=0.6, C=0.75 → **AW=0.32 (MEDIUM)**

---

### Cookie Forensics

**Attack Vector**: Persistent cookies survive browser cleaning.

**Flash Cookies (LSO)**: Stored separately, often not cleared.

**Attribution**:
```
Cookie: session_id=abc123 (set 2024-01-15)
Operational activity: 2024-01-15 onwards
→ Links browser session to operations timeline
```

**Attribution Weight**: V=0.6, R=0.7, C=0.6 → **AW=0.25 (LOW)**

---

## Network Forensics

### PCAP Analysis

**Attack Vector**: Packet captures reveal patterns despite encryption.

**Recoverable Intelligence**:
- DNS queries (even with DoH, initial bootstrap leaks)
- TLS SNI (Server Name Indication in cleartext)
- Packet sizes and timing (traffic analysis)
- Source/destination IPs

**Example**:
```bash
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort -u
# Lists all DNS queries despite TLS encryption
```

**Attribution Weight**: V=0.8, R=0.5, C=0.7 → **AW=0.28 (MEDIUM)**

---

### Log File Analysis

**Attack Vector**: Logs persist and correlate across systems.

**Common Logs**:
- `/var/log/auth.log` (SSH logins with timestamps and IPs)
- Web server access logs
- Application logs
- Firewall logs

**Timeline Correlation**:
```bash
# auth.log
2024-03-15 18:30:15 ssh login from 203.0.113.42
2024-03-15 19:45:22 ssh login from 203.0.113.42
2024-03-15 21:10:05 ssh login from 203.0.113.42

→ Consistent evening activity (timezone inference)
→ Same IP (infrastructure correlation)
```

**Attribution Weight**: V=0.7, R=0.8, C=0.8 → **AW=0.45 (MEDIUM)**

---

## Metadata Forensics

### Document Metadata

**Attack Vector**: Office documents, PDFs contain author information.

**Recoverable**:
- Author name
- Company/organization
- Software version
- Creation/modification timestamps
- File paths (leaks directory structure)

**Tool**:
```bash
exiftool document.pdf
# Author: John Doe
# Creator: Microsoft Word 16.0
# Create Date: 2024:03:15 18:30:00
# Modify Date: 2024:03:15 19:45:00
```

**OPSEC Failure**:
```
PDF metadata shows:
Author: operations@company.com
File path: C:\Users\JohnDoe\Documents\RedTeam\target_analysis.pdf

→ Real name, company, folder structure leaked
```

**Attribution Weight**: V=0.8, R=0.9, C=0.85 → **AW=0.61 (HIGH)**

---

### Image EXIF Data

**Attack Vector**: Photos contain GPS, camera model, timestamps.

**Critical Leaks**:
- GPS coordinates (lat/long)
- Camera make/model (device fingerprint)
- Software used (e.g., "Adobe Photoshop")
- Original filename

**Example**:
```bash
exiftool photo.jpg | grep GPS
GPS Position: 36°10'30.0"N 115°08'11.0"W
→ Las Vegas Convention Center (conference location)
```

**Attribution Weight**: V=0.9, R=1.0, C=0.9 → **AW=0.81 (CRITICAL)**

---

## USB/External Media Forensics

### USB Device History

**Windows Registry**: Tracks all USB devices ever connected.

**Registry Key**:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
```

**OPSEC Failure**:
```
Registry shows:
USB Device: "OperationalBackup_2024" (Serial: ABC123)
Last Connected: 2024-03-15 19:30

→ Links operator to specific USB device
→ If USB later seized, full correlation possible
```

**Attribution Weight**: V=0.6, R=0.8, C=0.75 → **AW=0.36 (MEDIUM)**

---

## Timeline Reconstruction

### Super Timeline Analysis

**Technique**: Combine all timestamps from system to build activity timeline.

**Tools**: `log2timeline` (Plaso)

**What Gets Correlated**:
- File access times
- Browser history
- Log files
- Registry changes
- Network connections

**Output**:
```
18:30 - SSH login from 203.0.113.42
18:32 - File created: malware.py
18:45 - Browser: google.com/search?q=cobalt+strike+tutorial
19:15 - File modified: malware.py
19:30 - Network: TCP connection to 198.51.100.10:4444
```

**Attribution Value**: Complete operational timeline reconstruction.

**Attribution Weight**: V=0.7, R=0.8, C=0.9 → **AW=0.50 (HIGH)**

---

## Cross-INT Forensic Correlations

### Forensics + OSINT
```
Forensic timeline: SSH logins 18:00-02:00 UTC
OSINT (GitHub): Commits 18:00-02:00 UTC
→ Timing correlation confirms same operator
```

### Forensics + GEOINT
```
Image EXIF: GPS coordinates
GEOINT: Satellite imagery of location
→ Physical location confirmed
```

### Forensics + HUMINT
```
Document metadata: Author "JohnDoe"
HUMINT (LinkedIn): Employee named John Doe at target company
→ Identity attribution
```

---

## Anti-Forensics Techniques

### 1. Secure Deletion
```bash
# Linux
shred -vfz -n 7 sensitive_file.txt

# Windows
cipher /w:C:\  # Wipe free space
```

### 2. Timestamp Manipulation
```bash
# Change file timestamps
touch -t 202001010000 file.txt  # Set to 2020-01-01
```

### 3. Metadata Scrubbing
```bash
# Remove EXIF from images
exiftool -all= photo.jpg

# Scrub PDF metadata
qpdf --linearize --decrypt input.pdf output.pdf
```

### 4. RAM Wiping on Shutdown
```bash
# Linux: Wipe RAM on shutdown
echo 3 > /proc/sys/vm/drop_caches
```

### 5. Full Disk Encryption
- Protects at-rest data
- Does NOT protect running system (memory forensics still works)

---

## Quantitative Forensic Risk Assessment

| Forensic Artifact | V | R | C | **AW** | Risk |
|-------------------|---|---|---|--------|------|
| Image EXIF GPS | 0.9 | 1.0 | 0.9 | **0.81** | CRITICAL |
| Document metadata (author) | 0.8 | 0.9 | 0.85 | **0.61** | HIGH |
| Super timeline | 0.7 | 0.8 | 0.9 | **0.50** | HIGH |
| Log file correlation | 0.7 | 0.8 | 0.8 | **0.45** | MEDIUM |
| File MAC times | 0.7 | 0.9 | 0.7 | **0.44** | MEDIUM |
| Deleted file recovery | 0.6 | 0.8 | 0.8 | **0.38** | MEDIUM |
| USB device history | 0.6 | 0.8 | 0.75 | **0.36** | MEDIUM |

**Composite Forensic Risk**: 0.94 → **CRITICAL**

---

## Conclusion

**Digital forensics defeats OPSEC through:**
1. Persistent metadata (timestamps, author info, EXIF)
2. Timeline correlation across artifacts
3. Deleted file recovery
4. Cross-INT fusion with OSINT/GEOINT/HUMINT

**Critical Defenses**:
- Metadata scrubbing (EXIF, PDF, Office docs)
- Secure deletion (shred, not just delete)
- Timestamp obfuscation
- Full disk encryption (necessary but not sufficient)

**Uncomfortable Truth**: If forensics gains physical access, most OPSEC is retroactively defeated.

---

*நீதியே வெல்லும்*

"Justice alone triumphs."

**Forensic evidence is the ultimate justice. Leave none behind.**
