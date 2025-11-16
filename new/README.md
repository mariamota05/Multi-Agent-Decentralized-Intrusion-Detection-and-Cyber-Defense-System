# SPADE Network Security Simulation

Multi-agent network security simulation with intelligent incident response using the SPADE framework.

## Overview

This project simulates a network with routers, nodes, attackers, and security agents that detect and respond to threats using the Contract Net Protocol (CNP). The system features:

- **Deterministic behavior** - No randomness, reproducible results
- **BFS routing** - Intelligent path selection considering router resources
- **Sophisticated incident response** - Different mitigation strategies for different threats
- **Real-time visualization** - Pygame-based network topology viewer
- **Resource tracking** - CPU and bandwidth monitoring for all agents

## Features

### Attack Types with Specialized Responses

#### 🦠 Malware → Aggressive Containment
- **Attack**: Low-volume malicious messages with trojan/virus/ransomware keywords
- **Response**: 
  1. Immediate permanent block (0.3s response time)
  2. Quarantine advisory sent to all nodes
  3. Fastest response - malware spreads quickly

#### 💥 DDoS → Graduated Response  
- **Attack**: High-volume bursts designed to overwhelm resources
- **Response**:
  1. Rate limiting applied first (10 msg/s throttle)
  2. Temporary 30-second block if rate limiting insufficient
  3. Monitoring scheduled for sustained attack patterns
  4. Proportionate response - less aggressive than permanent block

#### 👤 Insider Threat → Investigative Approach
- **Attack**: Gradual escalation from failed logins to data exfiltration
- **Response**:
  1. Account suspension (reversible soft block)
  2. Access audit initiated to log accessed resources
  3. Administrator alerts for human review
  4. Permanent block only after investigation confirms malicious intent
  5. Longest response time (0.7s) - requires careful handling

### Network Architecture

- **3 routers** in configurable topology (ring, mesh, star, or line)
- **2 nodes per router** (6 workstations total)
- **1 monitoring agent** per router for threat detection
- **2 incident response agents** competing via CNP auctions
- **1 attacker agent** with configurable attack type and intensity

## Installation

### Prerequisites

- Python 3.8 or higher
- XMPP server (Prosody recommended)
- Git (for cloning)

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd new/
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start XMPP server**
   
   Install and start Prosody (or your preferred XMPP server):
   ```bash
   # Ubuntu/Debian
   sudo apt install prosody
   sudo systemctl start prosody
   
   # macOS (Homebrew)
   brew install prosody
   prosody
   
   # Windows
   # Download from https://prosody.im/download/
   ```

4. **Configure XMPP accounts** (if auto-registration disabled)
   
   Create accounts on localhost for all agents:
   - Routers: `router0@localhost`, `router1@localhost`, `router2@localhost`
   - Nodes: `router0_node0@localhost`, `router0_node1@localhost`, etc.
   - Monitors: `monitor0@localhost`, `monitor1@localhost`, `monitor2@localhost`
   - Response: `response0@localhost`, `response1@localhost`
   - Attacker: `attacker0@localhost`

## Usage

### Basic Simulation

Run the simulation with default settings:

```bash
python new/environment.py --domain localhost --password secret --time 30
```

### Easy Configuration

Just edit the variables at the top of `environment.py` before running:

```python
# Network topology
NUM_ROUTERS = 3
NODES_PER_ROUTER = 2
ROUTER_TOPOLOGY = "ring"  # Options: "ring", "mesh", "star", "line"

# Attackers (leave empty [] for no attackers)
ATTACKERS = [
    ("stealth_malware", ["router0_node0@localhost"], 5, 20, 3),
]
# Format: (type, [targets], intensity, duration, delay)
# Types: "stealth_malware", "ddos", "insider_threat"
```

### Running Without Attackers

To test just the network and routing without any attacks:

```python
# In environment.py, set:
ATTACKERS = []
```

Then run normally:
```bash
python new/environment.py --time 30
```

### Multiple Attackers

Just add more items to the `ATTACKERS` list:

```python
ATTACKERS = [
    ("stealth_malware", ["router0_node0@localhost"], 5, 20, 3),
    ("ddos", ["router1_node0@localhost"], 8, 15, 5),
    ("insider_threat", ["router2_node0@localhost"], 6, 18, 7),
]
```

### Testing Message Types

Nodes understand these message formats:

| Message | Response | CPU Load | Duration | Use Case |
|---------|----------|----------|----------|----------|
| `PING` | `PONG` | 1.5% | 0.3s | Connectivity test |
| `REQUEST: <text>` | `RESPONSE: <text>` | 5% | 1.0s | Processing test |
| Any other text | (no reply) | 2% | 0.5s | Custom messages |

**Example scheduled messages:**
```python
SCHEDULED_MESSAGES = [
    (0, 0, 1, 1, "PING", 2),                    # Test connectivity
    (1, 1, 2, 0, "REQUEST: status", 5),         # Test processing
    (0, 1, 2, 1, "Hello from node 0", 8),       # Custom message
]
# Format: (from_router, from_node, to_router, to_node, message, delay_seconds)
```

## Configuration Examples

### Example 1: No Attackers (Routing Test)
```python
NUM_ROUTERS = 3
NODES_PER_ROUTER = 2
ROUTER_TOPOLOGY = "mesh"

ATTACKERS = []  # No attacks

SCHEDULED_MESSAGES = [
    (0, 0, 2, 1, "PING", 2),
    (1, 1, 2, 0, "REQUEST: status", 5),
]
```

### Example 2: Single DDoS Attack
```python
NUM_ROUTERS = 3
NODES_PER_ROUTER = 2
ROUTER_TOPOLOGY = "ring"

ATTACKERS = [
    ("ddos", ["router1_node0@localhost"], 8, 20, 3),
]

SCHEDULED_MESSAGES = []
```

### Example 3: Multiple Coordinated Attacks
```python
NUM_ROUTERS = 4
NODES_PER_ROUTER = 3
ROUTER_TOPOLOGY = "mesh"

ATTACKERS = [
    ("stealth_malware", ["router0_node0@localhost", "router0_node1@localhost"], 5, 25, 3),
    ("ddos", ["router1_node0@localhost"], 9, 20, 5),
    ("insider_threat", ["router2_node0@localhost"], 7, 22, 7),
]

SCHEDULED_MESSAGES = [
    (3, 0, 0, 0, "PING", 10),  # Test if routing still works during attacks
]
```

Run with default settings (stealth malware attack for 20 seconds):

```bash
python environment.py --time 20
```

### Configuration Options

Edit `environment.py` to customize:

```python
# Network topology
NUM_ROUTERS = 3
NODES_PER_ROUTER = 2
ROUTER_TOPOLOGY = "ring"  # Options: "ring", "mesh", "star", "line"

# Attack configuration
ATTACKER_TYPE = "stealth_malware"  # Options: "stealth_malware", "ddos", "insider_threat"
ATTACKER_INTENSITY = 5  # 1-10 (higher = more aggressive)
ATTACKER_DURATION = 20  # seconds
```

### Run Specific Attack Types

```bash
# DDoS attack (high-volume bursts)
# Edit environment.py: ATTACKER_TYPE = "ddos", ATTACKER_INTENSITY = 8

# Insider threat (gradual escalation)
# Edit environment.py: ATTACKER_TYPE = "insider_threat", ATTACKER_INTENSITY = 6
```

### With Visualization

The pygame visualization runs automatically if pygame is installed. See [README_PYGAME.md](README_PYGAME.md) for controls and features.

To disable visualization:
```python
# In environment.py
ENABLE_VISUALIZATION = False
```

## How It Works

### 1. Threat Detection

Monitoring agents inspect all network traffic for suspicious patterns:
- **Keyword scanning** - malware, virus, trojan, failed login, unauthorized
- **Rate-based detection** - multiple suspicious events from same sender
- **DDoS spike detection** - high message volume

### 2. Contract Net Protocol (CNP)

When a threat is detected:

1. **CFP (Call for Proposals)** - Monitor sends incident details to all response agents
2. **Proposals** - Response agents calculate availability score based on current workload
3. **Award** - Monitor selects best bidder (lowest workload)
4. **Execution** - Winner executes mitigation strategy
5. **Report** - Winner sends results back to monitor

### 3. Firewall Commands

Incident response agents send commands to node firewalls:

| Command | Purpose | Used By |
|---------|---------|---------|
| `BLOCK_JID:jid` | Permanent block | All strategies |
| `RATE_LIMIT:jid:10msg/s` | Throttle traffic | DDoS |
| `TEMP_BLOCK:jid:30s` | Temporary block | DDoS |
| `SUSPEND_ACCESS:jid` | Reversible suspension | Insider |
| `QUARANTINE_ADVISORY:incident` | Isolation recommendation | Malware |
| `ADMIN_ALERT:type:id:jid` | Human escalation | Insider |

## Resource Tracking

All agents track CPU and bandwidth usage through a **task-based system**. Each operation creates a temporary task that consumes resources for its duration.

### Task Naming System

When you see logs like `Active tasks: recv-9, send-12, t5-1731701234`, here's what each task type means:

| Task Name Format | What It Means | CPU Load | Duration | Example |
|-----------------|---------------|----------|----------|---------|
| `recv-N` | **Receiving a message** - Base processing overhead for parsing any incoming message | 2% | 0.5s | `recv-9` |
| `send-N` | **Sending a reply** - CPU cost of constructing and sending PING/PONG replies | 1.5% | 0.3s | `send-12` |
| `proc-N` | **Processing a request** - Handling REQUEST: messages (more intensive than simple receives) | 5% | 1.0s | `proc-3` |
| `t{N}-{timestamp}` | **Attack payload task** - Processing malicious content from attackers (load varies by attack type) | Variable | Variable | `t5-1731701234` |

**Task Counter (`N`)**: Sequential number that increments with each operation. Higher numbers = more activity on that node.

**Timestamp**: Unix timestamp showing when the task was created (for attack tasks).

### Example Log Interpretation

```
[17:14:06] [NodeAgent router0_node0@localhost] Resource update: cpu=12.0% bw=5.4% active_tasks=1
[17:14:06] [NodeAgent router0_node0@localhost] Active tasks: recv-9
```

**Translation:** 
- Node has **1 active task** currently running
- Task `recv-9` = This is the **9th message** this node has received
- CPU is at **12%** (base 10% + 2% from the receive task)
- Task will finish in **0.5 seconds** (receive tasks last 0.5s)

```
[17:14:15] [NodeAgent router1_node1@localhost] Active tasks: recv-23, t12-1731701655
```

**Translation:**
- Node has **2 active tasks** running simultaneously
- `recv-23` = Currently receiving its 23rd message (2% CPU, 0.5s)
- `t12-1731701655` = Processing an attack payload (variable CPU/duration based on attack type)
- Both tasks run in parallel, CPU loads add up

### Resource Consumption by Agent Type

**Nodes (Workstations/Servers):**
- Base idle: 10% CPU, 5% bandwidth
- Per `recv-N` task: +2% CPU for 0.5s
- Per `send-N` task: +1.5% CPU for 0.3s  
- Per `proc-N` task: +5% CPU for 1.0s
- Per attack task: Variable (see attack types below)

**Routers:**
- Base idle: 15% CPU, 8% bandwidth
- Per message routed: +2% CPU, +1.5% bandwidth
- Resource increases with `messages_routed` counter

**Incident Response:**
- Base idle: 10% CPU, 3% bandwidth
- Per active incident: +15% CPU, +5% bandwidth
- Only counts incidents with status="mitigating"

### Attack Task Loads

| Attack Type | Task CPU Load | Task Duration | Example Task |
|-------------|--------------|---------------|--------------|
| **Malware** | intensity × 5% | 3 seconds | `t8-1731701234` (25% CPU at intensity 5) |
| **DDoS** | intensity × 3% | 2 seconds | `t15-1731701240` (24% CPU at intensity 8) |
| **Insider Threat** | phase × 8% | 5 seconds | `t3-1731701250` (16% CPU in phase 2) |

### Why This Matters

Understanding tasks helps you:
- **Debug performance** - See which operations are causing high CPU
- **Identify attacks** - Attack tasks (`tN-timestamp`) have high loads and longer durations
- **Monitor activity** - Task counters show node workload (higher N = busier node)
- **Understand timing** - Know when resources will be freed (each task has fixed duration)

## BFS Routing

Routers use breadth-first search to find optimal paths:

```
Cost = hop_count × 1.0 + (cpu_usage + bandwidth_usage) / 200.0 × 0.5
```

This balances:
- **Minimum hops** - Shorter paths preferred
- **Resource utilization** - Avoids overloaded routers

## File Structure

```
new/
├── README.md                 # This file
├── README_PYGAME.md          # Visualization guide
├── PROJECT_REVIEW.md         # Detailed project review
├── IMPLEMENTATION_SUMMARY.md # Implementation completion summary
├── requirements.txt          # Python dependencies
├── environment.py            # Main entry point - creates all agents
├── node.py                   # NodeAgent - workstations/servers
├── router.py                 # RouterAgent - packet forwarding with BFS
├── monitoring.py             # MonitoringAgent - threat detection & CNP
├── response.py               # IncidentResponseAgent - CNP participant
├── attacker.py               # (legacy - use attackers/ folder instead)
├── firewall.py               # FirewallBehaviour - filtering & commands
├── visualizer.py             # NetworkVisualizer - pygame rendering
├── subnetwork.py             # (legacy/utility)
└── attackers/                # Specialized attack agents
    ├── README.md             # Attack bot documentation
    ├── malware_attacker.py   # 🦠 Malware/trojan attacks
    ├── ddos_attacker.py      # 💥 DDoS flood attacks
    └── insider_attacker.py   # 👤 Insider threat attacks
```

## Example Output

### Malware Attack
```
[17:14:00] [environment] 🦠 Created MALWARE attacker: attacker0@localhost
[17:14:00] [environment]    Targeting: ['router0_node0@localhost', 'router0_node1@localhost']
[17:14:00] [environment]    Intensity: 5/10, Duration: 30s
[17:14:05] [🦠 MALWARE] → router0_node0@localhost: ATTACK: Attempting to install trojan backdoor...
[17:14:05] [FIREWALL router0_node0@localhost] Threat detected from attacker0@localhost
[17:14:05] [MonitoringAgent monitor0@localhost] Starting CNP auction for incident_6: malware
[17:14:05] [IncidentResponse response0@localhost] WON contract for incident_6
[17:14:05] [IncidentResponse response0@localhost] MITIGATION: Malware containment - blocking attacker
[FIREWALL router0_node0@localhost] 🔒 QUARANTINE ADVISORY: malware_incident_6
```

### DDoS Attack
```
[17:15:00] [environment] 💥 Created DDoS attacker: attacker0@localhost
[17:15:00] [💥 DDoS] Attack plan: 3 bursts × 80 messages = 240 total
[17:15:00] [💥 DDoS] 🌊 BURST #1/3 - Sending 80 messages...
[17:15:01] [💥 DDoS] ✓ Burst #1 complete (80 messages sent)
[FIREWALL] Rate limit applied: attacker0@localhost -> 10 msg/s
[FIREWALL] Temporary block: attacker0@localhost for 30s
```

### Insider Threat Attack
```
[17:16:00] [environment] 👤 Created INSIDER THREAT attacker: attacker0@localhost
[17:16:00] [👤 INSIDER] Phase 1: Attempting credential access...
[17:16:00] [👤 INSIDER] → router0_node0@localhost: Phase 1 - ATTACK: Failed login attempt for admin user (try #1)...
[17:16:15] [👤 INSIDER] ⚠️ Phase 2: Escalating to unauthorized access attempts
[FIREWALL] Account suspended: attacker0@localhost
[FIREWALL] ⚠️  ADMIN ALERT: insider_threat
```

## Troubleshooting

### XMPP Connection Errors

```
Error: Connection refused on localhost:5222
```

**Solution:** Ensure XMPP server is running:
```bash
sudo systemctl status prosody
# or
ps aux | grep prosody
```

### Auto-Registration Fails

```
Error: Account registration not allowed
```

**Solution:** Manually create accounts or enable in-band registration in Prosody config:
```lua
-- /etc/prosody/prosody.cfg.lua
allow_registration = true
```

### Pygame Window Not Opening

```
ImportError: No module named 'pygame'
```

**Solution:** Install pygame or disable visualization:
```bash
pip install pygame
# or edit environment.py: ENABLE_VISUALIZATION = False
```

## Advanced Configuration

### Custom Network Topologies

```python
# Mesh - every router connects to every other (high redundancy)
ROUTER_TOPOLOGY = "mesh"

# Star - router 0 is hub, all others connect to it (centralized)
ROUTER_TOPOLOGY = "star"

# Line - routers in sequence 0-1-2-3 (linear)
ROUTER_TOPOLOGY = "line"

# Ring - routers in circle 0-1-2-3-0 (balanced)
ROUTER_TOPOLOGY = "ring"
```

### Adjust Resource Consumption

Edit node.py to change base loads:
```python
# Line ~133
base_cpu = 10.0  # Adjust base CPU usage
base_bw = 5.0    # Adjust base bandwidth usage
```

### Modify Mitigation Strategies

Edit response.py `execute_mitigation()` to customize responses:
```python
# Example: Add notification step to DDoS response
async def execute_mitigation(self, incident_id, threat_type, offender_jid):
    if threat_type == "ddos":
        # ... existing steps ...
        
        # Add: Send notification to admins
        notification = Message(to="admin@localhost")
        notification.body = f"DDoS attack from {offender_jid} mitigated"
        await self.send(notification)
```

## Performance

Tested configuration:
- 3 routers × 2 nodes = 6 workstations
- 3 monitors + 2 response agents + 1 attacker = 12 total agents
- ~50 messages/second during DDoS attack
- ~20% CPU usage on modern hardware
- Pygame visualization: 60 FPS

## Contributing

Contributions welcome! Areas for enhancement:
- Additional attack types (SQL injection, XSS, brute force)
- Machine learning-based threat detection
- Network traffic statistics and graphs
- Integration with real firewall systems
- Multi-hop BFS routing optimization

## License

Educational project - free to use and modify.

## Credits

Built with:
- **SPADE** - Smart Python Agent Development Environment
- **Pygame** - 2D visualization
- **XMPP/Prosody** - Agent messaging infrastructure

## Contact

For questions or issues, see PROJECT_REVIEW.md for detailed technical documentation.
