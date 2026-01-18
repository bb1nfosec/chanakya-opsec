# Browser OPSEC Failures & Attribution Vectors

## Overview

Browser-based OPSEC failures occur despite using VPNs, Tor, or privacy tools. Modern browsers leak extensive fingerprinting data that enables **highly accurate user tracking and attribution**.

**Key Insight**: Your browser is more unique than your fingerprint. Even "privacy browsers" leak identifying information.

---

## Critical Browser Leaks

### 1. WebRTC IP Leak (CRITICAL)

**Attack Vector**: WebRTC STUN requests bypass VPN/Tor and reveal true IP address.

**How It Works**:
```javascript
// Attacker JavaScript
var RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
var pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});

pc.createDataChannel("");
pc.createOffer().then(offer => pc.setLocalDescription(offer));

pc.onicecandidate = function(ice){
    if(ice.candidate){
        var ipRegex = /([0-9]{1,3}\.){3}[0-9]{1,3}/;
        var ipAddr = ipRegex.exec(ice.candidate.candidate)[0];
        console.log("True IP: " + ipAddr);  // Leaks real IP, not VPN IP!
    }
};
```

**Result**: True IP leaked even when browsing through Tor or VPN.

**Attribution Weight**: V=1.0, R=0.9, C=1.0 → **AW=0.90 (CRITICAL)**

**Defense**:
- Disable WebRTC in browser settings
- Use uBlock Origin with "Prevent WebRTC from leaking local IP addresses"
- Tor Browser automatically disables WebRTC

---

### 2. Canvas Fingerprinting

**Attack Vector**: HTML5 Canvas API creates unique fingerprint based on GPU, fonts, OS rendering.

**Uniqueness**: 99.9% of users have unique Canvas fingerprint.

**How It Works**:
```javascript
// Draw text and shapes to canvas
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.textBaseline = "top";
ctx.font = "14px 'Arial'";
ctx.fillText("Browser fingerprint test 🔒", 2, 2);

// Get hash of rendered pixels
var hash = canvas.toDataURL().substring(0, 50);
// This hash is unique per user (GPU + fonts + OS rendering)
```

**Attribution Weight**: V=0.9, R=0.7, C=0.85 → **AW=0.53 (HIGH)**

**Cross-Platform Correlation**: Same Canvas hash = same device/user across sites.

---

### 3. Font Enumeration

**Attack Vector**: Installed fonts create unique fingerprint (10,000+ combinations).

**Technique**:
```javascript
var fonts = ['Arial', 'Verdana', 'Comic Sans MS', /* ... 100+ fonts */];
var detected = [];
fonts.forEach(font => {
    if(isFontInstalled(font)) detected.push(font);
});
// detected array is unique per user
```

**Attribution Weight**: V=0.8, R=0.6, C=0.7 → **AW=0.34 (MEDIUM)**

---

### 4. Browser/Hardware Fingerprinting

**Collected Data**:
- Screen resolution, color depth
- CPU cores (`navigator.hardwareConcurrency`)
- GPU vendor/renderer (WebGL)
- Battery status (if available)
- Media devices (mic/camera enumeration)
- Installed browser extensions
- Timezone, language preferences

**Combined Fingerprint**: 99.5%+ unique users.

**Attribution Weight**: V=0.85, R=0.6, C=0.8 → **AW=0.41 (MEDIUM)**

---

### 5. DNS Prefetch Leaks

**Attack Vector**: Browser pre-resolves DNS even if link not clicked.

**HTML Trigger**:
```html
<!-- Hidden image loads, triggering DNS -->
<img src="http://tracking.example.com/user123.png" style="display:none">
```

**Result**: DNS query to `tracking.example.com` even if you never click anything.

**Attribution Weight**: V=0.7, R=0.8, C=0.6 → **AW=0.34 (MEDIUM)**

---

### 6. JavaScript Timing Attacks

**Attack Vector**: `performance.now()` reveals hardware/browser characteristics.

**Cache Timing**:
```javascript
// Measure if URL is in cache (visited before)
var img = new Image();
var start = performance.now();
img.src = "https://example.com/logo.png";
img.onload = () => {
    var elapsed = performance.now() - start;
    if(elapsed < 10) {
        console.log("Cached - you visited example.com before");
    }
};
```

**Attribution Weight**: V=0.6, R=0.5, C=0.6 → **AW=0.18 (LOW)**

---

## Cross-INT Browser Correlations

### Browser + DNS
**Attack Chain**:
1. WebRTC leaks true IP: 203.0.113.42
2. DNS queries from this IP to 8.8.8.8
3. VPN claims exit in Netherlands, but DNS resolver in Sweden
4. **Conclusion**: True location = Sweden (not Netherlands)

### Browser + OSINT
**Attack Chain**:
1. Canvas fingerprint: `abc123def456`
2. GitHub account commits always show same Canvas hash
3. Cross-reference: GitHub username → LinkedIn → Real identity

### Browser + HUMINT
**Attack Chain**:
1. Browser timezone: UTC+1
2. Activity pattern: 18:00-02:00 UTC
3. **Inference**: European operator, evenings only (hobby/side project)

---

## Defensive Techniques

### 1. Use Tor Browser
- Disables WebRTC by default
- Canvas poisoning (returns fake Canvas data)
- Uniform fingerprint (all Tor users look identical)

### 2. Browser Hardening
```
Firefox about:config:
- media.peerconnection.enabled = false (disable WebRTC)
- privacy.resistFingerprinting = true
- geo.enabled = false
```

### 3. Extension-Based Defenses
- uBlock Origin (block WebRTC leaks)
- CanvasBlocker (randomize Canvas)
- Decentraleyes (prevent CDN fingerprinting)

### 4. Avoid Cross-Site Correlation
- Separate browsers for operations vs. personal use
- Never log into personal accounts from operational browser
- Use Tor Browser for operational activity

---

## Quantitative Risk Assessment

| Signal | Visibility | Retention | Correlation | **AW** | Risk |
|--------|-----------|-----------|-------------|--------|------|
| WebRTC IP leak | 1.0 | 0.9 | 1.0 | **0.90** | CRITICAL |
| Canvas fingerprint | 0.9 | 0.7 | 0.85 | **0.53** | HIGH |
| Font enumeration | 0.8 | 0.6 | 0.7 | **0.34** | MEDIUM |
| Browser fingerprint | 0.85 | 0.6 | 0.8 | **0.41** | MEDIUM |
| DNS prefetch | 0.7 | 0.8 | 0.6 | **0.34** | MEDIUM |
| Timing attacks | 0.6 | 0.5 | 0.6 | **0.18** | LOW |

**Composite Browser Risk** (all signals): 0.97 → **CRITICAL**

---

## Conclusion

**Browser OPSEC failures happen even with VPN/Tor.**

Critical mitigations:
1. Use Tor Browser (not just Tor with regular browser)
2. Disable WebRTC (absolute priority)
3. Accept that perfect browser anonymity is nearly impossible
4. Compartmentalize: separate browsers for operations

---

*உண்மையே வெல்லும்*

"Truth alone triumphs."

**Your browser fingerprint IS the truth of your identity. Defend it.**
