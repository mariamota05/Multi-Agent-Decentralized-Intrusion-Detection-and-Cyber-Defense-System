# Attack Bots

This folder contains specialized attack agents, each implementing a different type of attack.

## Available Attackers

### 🦠 Malware Attacker (`malware_attacker.py`)

**What it does:** Infects nodes with persistent malware that degrades performance

**Characteristics:**
- Sends infection payloads (trojan, cryptominer, keylogger, ransomware, etc.)
- **Once infected:** Node gets +20% CPU overhead on EVERY message processed
- Infection persists until incident response sends cure command
- Low-volume periodic attacks (stealth timing)
- Attack period: Slower at low intensity, faster at high intensity

**Infection mechanism:**
1. Attacker sends `INFECT:malware.type` message
2. Node receives and processes infection (3% CPU initial load)
3. Node's internal state set to `malware_infection=True`
4. **ALL subsequent message processing** gets +20% CPU penalty
5. Simulates malware running in background (cryptominer, keylogger, etc.)
6. Only removable by incident response `CURE_INFECTION` command

**How to run:**
```bash
python attackers/malware_attacker.py \
  --jid attacker@localhost \
  --password secret \
  --targets router0_node0@localhost,router0_node1@localhost \
  --intensity 5 \
  --duration 30
```

**Expected response:**
- ✓ Immediate permanent block (stops new infections)
- ✓ Cure command sent to all nodes (removes existing infections)
- ✓ Quarantine advisory to all nodes
- ✓ Fastest response (0.3s - malware spreads fast!)

**Watch for in logs:**
- `⚠️  INFECTED with malware.type - All message processing +20% CPU!`
- `✓ CURED: malware.type removed - Performance restored!`

---

### 💥 DDoS Attacker (`ddos_attacker.py`)

**What it does:** Floods targets with high-volume message bursts

**Characteristics:**
- 3 bursts with 5-second intervals
- Burst size: intensity × 10 messages
- CPU load: intensity × 3% for 2 seconds per message

**How to run:**
```bash
python attackers/ddos_attacker.py \
  --jid attacker@localhost \
  --password secret \
  --targets router0_node0@localhost,router1_node0@localhost \
  --intensity 8
```

**Expected response:**
- ✓ Rate limiting (10 msg/s)
- ✓ Temporary 30-second block
- ✓ Monitoring scheduled

---

### 👤 Insider Threat Attacker (`insider_attacker.py`)

**What it does:** Gradual escalation from failed logins to data exfiltration

**Characteristics:**
- Phase 1: Failed login attempts (5 times)
- Phase 2: Unauthorized access (5 times)
- Phase 3: Data exfiltration (persistent)
- CPU load: phase × 8% (escalates: 8% → 16% → 24%)

**How to run:**
```bash
python attackers/insider_attacker.py \
  --jid attacker@localhost \
  --password secret \
  --targets router0_node0@localhost,router1_node1@localhost \
  --intensity 6 \
  --duration 40
```

**Expected response:**
- ✓ Account suspension (reversible)
- ✓ Access audit initiated
- ✓ Admin alerts sent
- ✓ Permanent block after investigation

---

## Log Output Comparison

### Malware Attacker Logs
```
[17:14:05] [🦠 MALWARE] Starting stealth malware attack from attacker@localhost
[17:14:05] [🦠 MALWARE] Attack period: 4.5s (intensity=5)
[17:14:05] [🦠 MALWARE] → router0_node0@localhost: ATTACK: Attempting to install trojan backdoor...
[17:14:10] [🦠 MALWARE] → router0_node1@localhost: ATTACK: Trying to inject malware payload...
```

### DDoS Attacker Logs
```
[17:15:00] [💥 DDoS] Starting DDoS attack from attacker@localhost
[17:15:00] [💥 DDoS] Attack plan: 3 bursts × 80 messages = 240 total
[17:15:00] [💥 DDoS] 🌊 BURST #1/3 - Sending 80 messages...
[17:15:01] [💥 DDoS] ✓ Burst #1 complete (80 messages sent)
[17:15:01] [💥 DDoS] ⏸️  Waiting 5 seconds before next burst...
```

### Insider Attacker Logs
```
[17:16:00] [👤 INSIDER] Starting insider threat attack from attacker@localhost
[17:16:00] [👤 INSIDER] Phase 1: Attempting credential access...
[17:16:00] [👤 INSIDER] → router0_node0@localhost: Phase 1 - ATTACK: Failed login attempt for admin user (try #1)...
[17:16:15] [👤 INSIDER] ⚠️ Phase 2: Escalating to unauthorized access attempts
[17:16:30] [👤 INSIDER] 🚨 Phase 3: Persistent data exfiltration attempts
```

---

## Quick Test Commands

Test each attacker individually (requires XMPP server running):

```bash
# Test malware attack (30 seconds)
python attackers/malware_attacker.py --jid malware@localhost --targets router0_node0@localhost --intensity 5 --duration 30

# Test DDoS attack (3 bursts)
python attackers/ddos_attacker.py --jid ddos@localhost --targets router0_node0@localhost --intensity 8

# Test insider threat (40 seconds, 3 phases)
python attackers/insider_attacker.py --jid insider@localhost --targets router0_node0@localhost --intensity 6 --duration 40
```

---

## Benefits of Separate Files

✅ **Clearer logs** - Each attacker has distinct emoji and prefix  
✅ **Easier to understand** - One file = one attack type  
✅ **Simpler testing** - Run individual attacks without configuration changes  
✅ **Better documentation** - Each file explains its specific attack strategy  
✅ **Flexible deployment** - Mix and match different attackers simultaneously
