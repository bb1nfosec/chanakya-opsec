# Operational Tradecraft Manual

## Classification: UNCLASSIFIED // FOR OFFICIAL USE ONLY

**Target Audience:** Intelligence operatives, undercover agents, high-risk journalists, targeted activists

**Threat Model:** Physical surveillance, SIGINT collection, HUMINT operations, hotel room compromise

---

## I. Hotel & Lodging OPSEC

### 1.1 Hotel Selection Criteria

**Threat:** Room bugs, hidden cameras, physical access by intelligence services, key card logs

**Selection Protocol:**
```
LOW RISK:
- Major international chains (Marriott, Hilton)
- Business hotels with high turnover
- Self-check-in kiosks (minimal human interaction)

MEDIUM RISK:
- Local hotels (unknown loyalty)
- Hotels near government buildings (surveillance)
- Boutique hotels (fewer guests = easier to track)

HIGH RISK:
- State-owned hotels (direct intelligence access)
- Hotels requiring passport deposit (HUMINT collection)
- Hotels with mandatory police registration (China, Russia)

AVOID:
- Hotels near embassies, military bases
- Hotels known for intelligence service presence
```

**Booking OPSEC:**
```
DO:
- Book via VPN from non-target country
- Use burner email + prepaid credit card
- Check-in under alias (if legally permissible)
- Pay cash at check-in (avoid credit card trail)
- Request room change after check-in (pre-bugged room avoidance)

DON'T:
- Use loyalty programs (identity linkage)
- Provide real passport to hotel (if avoidable)
- Book from same IP as previous operations
```

---

### 1.2 Hotel Room Technical Surveillance Counter-Measures (TSCM)

**Upon Entry:**

**Step 1: Visual Inspection (5 minutes)**
```
Check for:
1. Smoke detectors (common camera hiding spot)
   - Look for pinhole in center
   - Check if LED is real or camera lens
   - Unscrew and inspect interior

2. Electrical outlets
   - USB charging ports (built-in cameras/mics)
   - Unusual outlet placement (wall-facing)

3. Mirrors
   - Fingernail test: Touch mirror, gap = real, no gap = two-way
   - Check edges for seams (hidden cameras behind)

4. Bed headboard
   - Screws/holes facing bed (camera placement)

5. Air vents
   - Pinhole cameras common in vents

6. Decorative items
   - Picture frames, clocks, tissue boxes
   - Anything with a "view" of the bed

7. Bathroom
   - Shower head (audio bugs)
   - Towel hooks (cameras facing toilet/shower)
```

**Step 2: RF (Radio Frequency) Detection (10 minutes)**

**Equipment Required:**
- RF detector (Raksa-120, KJB DD1206)
- Infrared camera (smartphone with IR filter removed)
- Non-linear junction detector (NLJD) - advanced

**Procedure:**
```bash
# RF Sweep
1. Turn on RF detector
2. Sweep entire room in grid pattern
3. Pay attention to:
   - 900 MHz / 2.4 GHz (WiFi cameras)
   - 433 MHz (wireless bugs)
   - Cellular frequencies (GSM bugs)

# Common bug frequencies:
- 88-108 MHz (FM transmitters)
- 2.4 GHz (WiFi/Bluetooth)
- 5.8 GHz (HD wireless cameras)

# Detection:
RF detector alarm = transmitter detected
→ Locate source, photograph, do NOT touch
→ Report to authorities OR leave hotel
```

**Step 3: Infrared Camera Sweep (2 minutes)**
```
Use smartphone with IR camera (or remove stock camera IR filter):
1. Turn off room lights
2. Scan room with phone camera
3. Look for purple/white LED lights (invisible to naked eye)
4. Hidden cameras use IR LEDs for night vision
5. Common locations: smoke detector, desk lamp, TV
```

**Step 4: Physical Search (15 minutes)**
```
Advanced check:
1. Unscrew smoke detector → inspect internals
2. Check lamp bases for wiring anomalies
3. Inspect phone line (wire tap possible)
4. Check under furniture for RF transmitters
5. Ceiling tiles (if accessible)
6. Behind wall art/paintings

Use flashlight to check dark corners for:
- Tiny holes (pinhole cameras = 1-2mm)
- Lens reflections
```

**Step 5: WiFi Network Analysis**
```bash
# Use laptop
# Scan for hidden WiFi cameras

# Linux:
sudo airodump-ng wlan0

# Look for SSIDs like:
"CAMERA-XXX"
"IPCAM_XXX"
"WIFI-CAM"
Hidden networks with strong signal (close proximity)

# Windows:
netsh wlan show networks mode=bssid

# Check for unusual networks with strong RSSI
```

**If Bug/Camera Found:**
```
DO:
- Photograph evidence (don't touch)
- Request immediate room change
- Report to hotel management (if trustworthy)
- File police report (creates paper trail)
- Leave hotel if high-threat environment

DON'T:
- Touch or disable device (fingerprints/evidence)
- Confront hotel staff immediately (may be complicit)
- Stay in room (assume full compromise)
```

---

### 1.3 Hotel Room Operational Security

**Secure Communications:**
```
NEVER:
- Make sensitive calls from hotel phone (wiretapped)
- Use hotel WiFi without VPN (monitored)
- Discuss operational matters in room (assume bugged)

ALWAYS:
- Use burner phone with fresh SIM
- Encrypt all communications (Signal, Off-the-Record)
- Conduct sensitive discussions outside (parks, public spaces)
```

**Physical Security:**
```
Door Security:
1. Use portable door lock (Addalock, portable door jammer)
2. Wedge rubber doorstop under door
3. Place glasses/bottles on door handle (alarm if opened)
4. Do NOT use "Do Not Disturb" sign (signals presence)

Window Security:
1. Close curtains completely (prevent visual surveillance)
2. Check for exterior window access (fire escape, adjacent balcony)
3. Tape over window gaps (prevent laser microphone)

Safe Usage:
- NEVER use hotel safe (hotel has master code)
- Use portable travel safe with own lock
- Or keep valuables on person at all times
```

**Departure Protocol:**
```
Before leaving room:
1. Full sweep for accidentally left items
2. Check under bed, in drawers, bathroom
3. Wipe surfaces for fingerprints (if high-threat)
4. Remove all trash (receipts, notes)
5. Factory reset any burner devices used in room
```

---

## II. Travel & Transportation OPSEC

### 2.1 Airport Surveillance Counter-Measures

**Threat:** CCTV (facial recognition), passport scans, electronic device searches, behavior detection

**Pre-Flight:**
```
72 hours before:
- Factory reset phone, laptop
- Remove all sensitive apps (Signal, Tor, VPN)
- Backup data to encrypted cloud (access after border)
- Create cover story for travel (business, tourism)

24 hours before:
- Sanitize social media (delete anti-government posts)
- Print physical boarding pass (avoid phone unlock at gate)
- Prepare decoy device (old phone with innocuous content)
```

**At Airport:**
```
DO:
- Arrive early (rushed = suspicious)
- Use automated kiosks (minimal human interaction)
- Wear common clothing (avoid standing out)
- Avoid extended eye contact with security
- Maintain calm, confident demeanor

DON'T:
- Take photos of security checkpoints (suspicious)
- Argue with security (escalation)
- Carry controversial books, t-shirts
- Joke about bombs/terrorism (instant flagging)
```

**Device Search Scenario (US/China/Russia):**
```
If asked to unlock device:

LEGAL OPTIONS (USA):
- Politely decline (5th Amendment - self-incrimination)
- Consequence: Device seizure + extended detention
- Lawyer contact: ACLU, EFF

FORCED COMPLIANCE (China/Russia):
- Cannot refuse without arrest
- Prepare decoy device in advance
- Real device left at home, cloud-sync after entry

COMPROMISE DEVICE:
- Assume fully imaged by authorities
- All data exfiltrated
- Factory reset immediately after crossing
```

---

### 2.2 Train/Bus OPSEC

**Physical Surveillance:**
```
Boarding:
- Board last minute (prevent tail from boarding)
- Change cars after boarding (lose tail)
- Sit near emergency exists (tactical positioning)

During Travel:
- Avoid sleeping (vulnerable state)
- Keep devices in sight (prevent Evil Maid attack)
- Use privacy screen on laptop (visual OPSEC)

Exit Strategy:
- Disembark at next-to-last station (throw off tail)
- Change trains (surveillance detection route)
```

---

### 2.3 Vehicle OPSEC

**Rental Car:**
```
DO:
- Pay cash + fake ID (if legal)
- Decline GPS/OnStar (telemetry tracking)
- Visual inspection for GPS trackers
  - Check: wheel wells, under seats, bumpers
  - Use RF detector to sweep for active trackers

DON'T:
- Use personal credit card (linkage)
- Input destinations into GPS (stored history)
- Leave rental agreement in car (identity document)
```

**GPS Tracker Detection:**
```
Equipment:
- RF detector (detects transmitting trackers)
- Flashlight + mirror (visual inspection)

Procedure:
1. Park in underground garage (block GPS signal)
2. RF sweep entire vehicle exterior

Common hiding spots:
- Wheel wells (magnetic mount)
- Under dashboard
- Inside bumpers
- OBD-II port (hardwired)

If tracker found:
- Photograph + leave in place (don't alert adversary)
- OR remove and place on different vehicle (misdirection)
```

---

## III. Telephone & Communication OPSEC

### 3.1 Telephone OPSEC (Traditional Calls)

**Threat:** Content intercept, metadata collection, voice recognition, caller ID

**Never Discuss Operational Details:**
```
FORBIDDEN TOPICS:
- Names, locations, times
- Plans, targets, methods
- Sensitive personal info

SAFE TOPICS:
- Generic small talk
- Pre-arranged code phrases
- Schedule in-person meeting
```

**Burner Phone Protocol:**
```
Purchase:
- Cash payment, no ID
- Different store per SIM
- Never same location twice

Usage:
- 1 SIM per operation (burn after use)
- Never call same number twice
- Remove battery when not in use (prevent tracking)
- Disable GPS, WiFi, Bluetooth

Disposal:
- SIM chip destruction (scissors, hammer)
- Phone: Remove battery, break screen, dispose separately
- Trash in public bin far from operational area
```

**Payphone OPSEC (if available):**
```
DO:
- Use gloves (fingerprints)
- Face away from CCTV
- Time calls < 3 minutes (harder to trace)
- Use pre-paid calling card (not credit card)

DON'T:
- Use payphones near operational area
- Call from same payphone twice
- Make patterns (same time/location)
```

---

### 3.2 IMSI Catcher Detection

**Threat:** StingRay/IMSI catcher (fake cell tower) intercepts calls/SMS

**Detection Methods:**

**App-Based (Android):**
```
SnoopSnitch:
- Detects IMSI catchers
- Alerts on baseband attacks
- Monitors cell tower changes

AIMSICD:
- Tracks cell tower locations
- Alerts on suspicious towers
- Maps unusual patterns

Indicators:
- Sudden drop to 2G (IMSI catchers force downgrade)
- Multiple devices lose signal simultaneously
- Tower location changes but phone static
```

**Manual Detection:**
```
Check network mode:
Settings → About → Network

Suspicious signs:
- 2G while in 4G area (forced downgrade)
- "Emergency calls only" in populated area
- Calls disconnecting frequently
- Unusual tower ID (LAC/CID change)

Response:
- Enable airplane mode immediately
- Move to different location (1+ km)
- Re-enable and check if normal
```

**Hardware-Based:**
```
IMSI Catcher Detector Devices:
- Cryptophone GSMK
- ESD Overwatch
- ~$1,000-5,000 USD

Features:
- Real-time IMSI detection
- Encrypted voice over cellular
- Visual/audio alerts
```

---

### 3.3 Encrypted Communications

**Voice Encryption:**
```
RECOMMENDED:
Signal (E2EE voice calls):
- Open source, audited
- Minimal metadata
- Disappearing messages

Avoid if possible (use in-person):
- Any call is metadata (who, when, duration, location)
- Signal still leaks metadata to Signal servers
```

**Text Communications:**
```
TIER 1 (Best):
- In-person communication
- Written notes (burn after reading)
- Dead drop (no direct contact)

TIER 2 (Good):
- Signal with disappearing messages (5 seconds)
- No phone numbers (use usernames only)
- Verify safety numbers (防止 MITM attack)

TIER 3 (Acceptable):
- PGP-encrypted email (ProtonMail)
- Jabber/XMPP with OTR (Off-the-Record)

NEVER:
- SMS (plaintext)
- WhatsApp (owned by Meta, backdoors possible)
- Telegram normal chats (not E2EE)
```

---

## IV. Physical Surveillance & Counter-Surveillance

### 4.1 Surveillance Detection Route (SDR)

**Objective:** Determine if being followed

**Basic SDR (30-60 minutes):**
```
Route Planning:
1. Start at point A (hotel, meeting location)
2. Create looping route with natural stops
3. End at point B (operational location)

Techniques:
1. **The Four Corners:**
   - Walk around city block
   - Turn right 4 times (return to start)
   - Tail must follow or lose visual

2. **Choke Point:**
   - Enter narrow street/alley (one entrance/exit)
   - Wait, observe who follows

3. **Reflection Check:**
   - Use store windows, car mirrors
   - Casual glance, don't stare

4. **Sudden Stop:**
   - Tie shoelace, check phone
   - Tail must stop or pass (blown cover)

5. **Transportation Switch:**
   - Enter subway, exit at next stop
   - Board bus, exit immediately
   - Taxi with sudden direction change

6. **Public Space Pause:**
   - Coffee shop, bookstore (15 min)
   - Observe entrance for arrivals

Indicators of Surveillance:
- Same person seen 3+ times in different locations
- Person matches pace/stops when you stop
- Eye contact then quick look away
- Communication device usage after you move
- Unnatural loitering
```

**Advanced SDR (2+ hours):**
```
Multi-Modal Transport:
1. Walk → Bus → Walk → Subway → Walk
2. Taxi → Walk → Taxi (different direction)

Dead End Test:
- Enter cul-de-sac
- Only one exit
- Wait, observe followers

Countersurveillance Team (if available):
- Friend follows you at distance
- Identifies tails
- Radio communication
```

---

### 4.2 Evasion Tactics

**If Surveillance Confirmed:**

**Immediate:**
```
1. Abort current operation
2. Do NOT go to operational location
3. Return to safe house via SDR
4. Do NOT use phone (location tracking)
```

**Evasion:**
```
Crowds:
- Enter crowded area (mall, market)
- Change appearance (remove jacket, hat)
- Exit different entrance

Public Transport:
- Board train, exit at last second (tail can't follow)
- Use multi-level shopping centers (lose visual)

Taxi Evasion:
- Hail taxi, get in back seat
- Immediately exit other side in traffic
- Enter building while tail stuck in car
```

---

## V. Meeting & Dead Drop Tradecraft

### 5.1 Secure Meeting Protocol

**Location Selection:**
```
GOOD:
- Public parks (open space, no cameras)
- Outdoor cafes (noise cover, escape routes)
- Moving locations (walking, ferry)

AVOID:
- Government buildings (cameras)
- Hotels (room bugs)
- Enclosed spaces (no escape)
```

**Pre-Meeting:**
```
1. SDR (confirm no tail)
2. Arrive early (30 min)
3. Identify exits, surveillance cameras
4. Position with view of entrance
5. Note operational vehicle
```

**During Meeting:**
```
DO:
- Keep conversation generic (assume audio surveillance)
- Use hand-delivered notes (burn after)
- Time-limited (< 30 minutes)
- Confirm next contact protocol

DON'T:
- Exchange devices (physical evidence)
- Use names
- Discuss specifics (write them down)
```

---

### 5.2 Dead Drop Operations

**Concept:** Asynchronous communication (no direct contact)

**Location Selection:**
```
GOOD:
- Public restroom (stall cistern)
- Park bench (taped under seat)
- Tree hollow (natural concealment)
- Magnetic container (under bridge, metal surface)

CRITERIA:
- Publicly accessible
- Not under CCTV
- Natural reason to visit
- Quickly accessible (< 30 seconds)
```

**Protocol:**
```
Loader (Person A):
1. SDR to location
2. Place package + mark signal
3. Exit normally
4. Signal to unloader (chalk mark, online signal)

Signal Location:
- Different than dead drop
- Visible from distance
- Chalk mark on wall, lamp post
- Online: Post specific emoji in public forum

Unloader (Person B):
1. Check signal location
2. SDR to dead drop
3. Retrieve package quickly
4. Exit normally
5. Remove signal mark

Timing:
- Loader and unloader NEVER meet
- Time separation: 30+ minutes minimum
```

---

## VI. Cross-Border & International OPSEC

### 6.1 Land Border Crossings

**Low-Security Borders (Schengen Area):**
```
- Minimal checks
- No passport stamps
- Random vehicle inspections

OPSEC:
- Clean vehicle (no suspicious items)
- Cover story prepared
- Cash for tolls (no credit card trail)
```

**High-Security Borders (US-Mexico, China-Russia):**
```
Preparation:
- Sanitized devices
- No sensitive documents
- Plausible cover story
- Legal representation contact info

At Border:
- Be polite, cooperative
- Answer questions minimally
- Do NOT volunteer information
- Request lawyer if detained
```

---

### 6.2 Maritime/Aviation Private Entry

**Private Aircraft:**
```
OPSEC Benefits:
- No TSA screening
- Minimal customs (general aviation)
- Flexible routing

Risks:
- Tail number tracking (public FlightAware)
- Customs declaration still required
- High cost

Mitigation:
- Charter via third party (not own name)
- Use overseas carrier
- File flight plan last minute
```

---

## VII. Vacation & Public Appearance OPSEC

### 7.1 Vacation Security

**Social Media:**
```
NEVER Post:
- Real-time location
- Hotel name, room number
- Photos with identifying background
- Travel dates in advance

SAFE Posting:
- After returning home
- Generic "beach" without location
- No metadata (EXIF stripped)
```

**Credit Card Usage:**
```
Vacation spending pattern = behavioral fingerprint

OPSEC:
- Use cash where possible
- Pre-paid debit card (not linked to identity)
- Avoid loyalty programs (Marriott Rewards, airline miles)
```

---

### 7.2 Restaurant/Public Dining

**Seating:**
```
DO:
- Sit with back to wall (tactical awareness)
- Face entrance (see arrivals)
- Near emergency exit

DON'T:
- Sit near windows (visual surveillance)
- Face wall (no situational awareness)
```

**Conversation:**
```
- Assume adjacent tables are adversaries
- Use "white noise" (background music)
- Discuss sensitive topics outside only
```

---

## VIII. Emergency Protocols

### 8.1 Compromise Response

**If Operational Cover Blown:**
```
Immediate (< 5 minutes):
1. Abort current activity
2. Destroy sensitive materials
3. Leave area immediately
4. Disable all electronic devices

Short-term (< 2 hours):
1. Exfiltration to safe house
2. Contact handler/support
3. Assess damage

Long-term:
1. Burn all operational identities
2. Change location (different city/country)
3. New cover identity
```

---

### 8.2 Arrest Protocol

**If Detained:**
```
SAY:
"I want a lawyer. I will not answer questions."

Then: SILENCE (literally nothing else)

DON'T:
- Explain yourself (prosecution evidence)
- Small talk (building rapport = interrogation tactic)
- Sign anything without lawyer

REMEMBER:
- Anything you say CAN and WILL be used against you
- Police can lie legally
- Nice cop/bad cop = script
- Silence is NOT guilt
```

---

## IX. Psychological OPSEC

### 9.1 Stress Management

**High-Stress Operations:**
```
Signs of Burnout:
- Paranoia (everyone is surveillance)
- Insomnia
- Breaking protocols (carelessness from exhaustion)

Mitigation:
- Mandatory rest days
- Rotate operational tempo
- Debrief with trusted colleague
- Exit strategy (know when to abort)
```

---

## X. Operational Checklists

### 10.1 Daily Operational Checklist

```
☐ Morning:
  ☐ Check burner phone charge
  ☐ Planned SDR route
  ☐ Cover story rehearsed
  ☐ Emergency contact protocol ready

☐ Before Leaving Safe House:
  ☐ Sensitive materials stored securely
  ☐ Devices encrypted/powered off
  ☐ Appearance appropriate for cover
  ☐ No operational documents on person

☐ After Operation:
  ☐ SDR completed (no tail)
  ☐ Debrief notes written + encrypted
  ☐ Burner devices recharged/replaced
  ☐ No operational talk in safe house (assume bugged)

☐ Weekly:
  ☐ Rotate burner SIMs
  ☐ Change safe house location
  ☐ Update emergency exfiltration plan
  ☐ Audit operational security (review logs)
```

---

## XI. Legal & Ethical Considerations

**This manual is for:**
- Authorized intelligence operations
- Security researchers
- Journalists in hostile countries
- Individuals under targeted surveillance

**NOT for:**
- Criminal activity
- Unlawful surveillance
- Violating laws without lawful authority

**Know Your Legal Protections:**
- Fifth Amendment (USA - self-incrimination)
- Legal Aid / EFF / ACLU (free legal support)
- Press protections (if journalist)

---

## XII. References

### Professional Training:
- CIA Tradecraft Manuals (FOIA released)
- MI6 HUMINT Field Procedures
- Surveillance Detection Course (Tony Scotti)

### Books:
- "Spy Craft" (Melton & Wallace)
- "The Spy and the Traitor" (Ben Macintyre)
- "Bodyguard of Lies" (Anthony Cave Brown)

### Equipment Suppliers:
- SpyAssociates.com (TSCM equipment)
- CounterSpy Shop (RF detectors)
- SpyGuy (surveillance detection tools)

---

**Related Documentation:**
- [[Geographic OPSEC]] - Country-specific threats
- [[APT Operations]] - Advanced digital tradecraft
- [[Personal OPSEC Checklist]] - Daily hygiene

---

*知己知彼，百战不殆*

"Tradecraft is discipline. Discipline is survival."

**The operative is always operational. There are no days off.**
