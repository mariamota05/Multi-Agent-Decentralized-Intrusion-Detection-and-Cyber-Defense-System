# Attacker Refactoring - Before vs After

## What Changed?

The monolithic `attacker.py` has been replaced with **three specialized attack bots** in the `attackers/` folder.

---

## Before (Old System)

### Single File: `attacker.py`
```python
# One complex file with all attack types
class AttackerAgent(Agent):
    class StealthMalwareBehaviour(PeriodicBehaviour):
        # Malware code...
    
    class DDoSBehaviour(CyclicBehaviour):
        # DDoS code...
    
    class InsiderThreatBehaviour(PeriodicBehaviour):
        # Insider code...
```

### Configuration Required
```python
# In environment.py
ATTACKER_TYPE = "stealth_malware"  # Had to change this to switch attacks
```

### Log Output (Confusing)
```
[17:14:05] [Attacker attacker0@localhost] Sent malware message...
[17:15:10] [Attacker attacker0@localhost] Sent DDoS burst...
```
❌ Same prefix for different attack types  
❌ Hard to distinguish between attacks  
❌ No visual indicators

---

## After (New System)

### Three Specialized Files

```
attackers/
├── malware_attacker.py   # 🦠 Only malware attacks
├── ddos_attacker.py      # 💥 Only DDoS attacks
└── insider_attacker.py   # 👤 Only insider threats
```

### Each File is Independent
```python
# malware_attacker.py
class MalwareAttacker(Agent):
    class StealthMalwareBehaviour(PeriodicBehaviour):
        # Only malware code - simple and focused!
```

### Log Output (Crystal Clear)
```
[17:14:05] [🦠 MALWARE] → router0_node0@localhost: ATTACK: Attempting to install trojan...
[17:15:00] [💥 DDoS] 🌊 BURST #1/3 - Sending 80 messages...
[17:16:15] [👤 INSIDER] ⚠️ Phase 2: Escalating to unauthorized access attempts
```
✅ Unique emoji for each attack  
✅ Clear attack type in prefix  
✅ Visual progress indicators  
✅ Phase information for insider attacks

---

## Benefits Comparison

| Feature | Before (attacker.py) | After (attackers/) |
|---------|---------------------|-------------------|
| **Clarity** | ❌ All attacks mixed | ✅ One file = one attack |
| **Logs** | ❌ Same prefix | ✅ Unique emoji & prefix |
| **Testing** | ❌ Edit config file | ✅ Run individual file |
| **Understanding** | ❌ 300+ lines to read | ✅ ~150 lines per file |
| **Documentation** | ❌ One docstring | ✅ Each file self-documents |
| **Flexibility** | ❌ One attacker at a time | ✅ Run multiple simultaneously |

---

## Usage Comparison

### Before: Running DDoS Attack
```bash
# Step 1: Edit environment.py
ATTACKER_TYPE = "ddos"
ATTACKER_INTENSITY = 8

# Step 2: Run environment
python environment.py --time 30
```

### After: Running DDoS Attack

**Option 1: Through environment.py (same as before)**
```bash
# Edit environment.py
ATTACKER_TYPE = "ddos"
ATTACKER_INTENSITY = 8

# Run
python environment.py --time 30
```

**Option 2: Standalone (NEW!)**
```bash
# Run attacker directly - no editing!
python attackers/ddos_attacker.py \
  --jid ddos@localhost \
  --targets router0_node0@localhost \
  --intensity 8
```

---

## Log Readability Example

### Before
```
[17:14:05] [Attacker attacker0@localhost] Starting stealth malware attack...
[17:14:05] [Attacker attacker0@localhost] Sent malware message to router0_node0@localhost: ATTACK: Attempting to install ...
[17:14:10] [Attacker attacker0@localhost] Sent malware message to router0_node1@localhost: ATTACK: Trying to inject malwa...
```
**Problem:** All lines look identical - hard to scan quickly

### After
```
[17:14:00] [🦠 MALWARE] Starting stealth malware attack from attacker@localhost
[17:14:00] [🦠 MALWARE] Attack period: 4.5s (intensity=5)
[17:14:05] [🦠 MALWARE] → router0_node0@localhost: ATTACK: Attempting to install trojan backdoor...
[17:14:10] [🦠 MALWARE] → router0_node1@localhost: ATTACK: Trying to inject malware payload...
```
**Solution:** 
- ✅ Emoji makes it instantly recognizable
- ✅ Arrow (→) clearly shows target
- ✅ Clean, scannable format

---

## Testing Individual Attacks

### Malware Test
```bash
python attackers/malware_attacker.py \
  --jid malware@localhost \
  --targets router0_node0@localhost \
  --intensity 5 \
  --duration 30
```

Expected response:
- 🔒 Quarantine advisory
- ⚡ Immediate permanent block
- ⏱️ 0.3s response time

### DDoS Test
```bash
python attackers/ddos_attacker.py \
  --jid ddos@localhost \
  --targets router0_node0@localhost \
  --intensity 8
```

Expected response:
- 📊 Rate limiting (10 msg/s)
- ⏰ Temporary 30s block
- 👁️ Monitoring scheduled

### Insider Test
```bash
python attackers/insider_attacker.py \
  --jid insider@localhost \
  --targets router0_node0@localhost \
  --intensity 6 \
  --duration 40
```

Expected response:
- 🚫 Account suspension
- 📝 Access audit
- ⚠️ Admin alerts
- 🔒 Permanent block after investigation

---

## Summary

### What You Gain
✅ **Clearer logs** - Emoji + unique prefixes  
✅ **Easier testing** - Run attacks individually  
✅ **Better understanding** - Each file explains one attack  
✅ **Simpler code** - 150 lines vs 300+ lines  
✅ **More flexible** - Mix and match attackers  

### What Stays the Same
✅ **Same functionality** - All attacks work identically  
✅ **Same config** - environment.py still works  
✅ **Same responses** - Mitigation strategies unchanged  
✅ **No breaking changes** - Existing scripts still run  

### Migration Path
- Old `attacker.py` still exists (can be deleted)
- New `attackers/` folder has replacements
- `environment.py` automatically uses new system
- No changes needed to other files
