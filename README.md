## 🛡️ Self-Healing Multi-Agent Network Security Simulation

This project implements a scalable, distributed network environment using the **SPADE** framework for simulating a self-healing security system. The system uses a network of **Nodes**, **Routers**, **Monitoring Agents**, and **Incident Response Agents** that employ the **Contract Net Protocol (CNP)** to autonomously detect, bid on, and mitigate cyber threats.

The environment is designed to stress-test decentralized security measures against various sophisticated attack types. 

---

## 💻 Project Structure

The core logic of the multi-agent system is organized as follows:

| File/Directory | Description |
| :--- | :--- |
| `environment.py` | **Main Entrypoint.** Orchestrates topology creation, initializes all SPADE agents (Routers, Nodes, Monitors, Attackers), manages the simulation lifecycle, and performs final metric reporting. |
| `router.py` | Implements the **RouterAgent**, which handles message forwarding (using intelligent BFS-based routing), resource tracking, and contains the `RouterFirewallBehaviour`. |
| `node.py` | Implements the **NodeAgent**, which simulates a workstation/server. Features: Resource simulation (CPU/BW), service response (PING/PONG), firewall integration, malware/insider threat vulnerability logic, and self-isolation/backlog containment. |
| `monitoring.py` | Implements the **MonitoringAgent**. Detects suspicious traffic (rate-based and keyword-based heuristics) and acts as the **CNP Initiator**, sending CFPs (Call for Proposals) to response agents upon alert. |
| `response.py` | Implements the **IncidentResponseAgent**. Acts as a **CNP Participant**, calculates its availability score (based on CPU/load), bids on incidents, and executes phased mitigation procedures (blocking, rate limiting, curing, forensic clean) upon winning a contract. |
| `firewall.py` | Defines the `FirewallBehaviour` base class and `RouterFirewallBehaviour`. Manages blocklists, rate limits, temporary blocks, and performs threat detection on messages. |
| `attackers/` | Directory containing specialized attacker agents: `ddos_attacker.py`, `malware_attacker.py`, and `insider_attacker.py`. |

---

## 🔥 Attack Scenarios

The simulation tests the CNP-based security response against three primary threats:

1.  **DDoS Attack (`ddos_attacker.py`)**: Sends high-volume bursts to overwhelm node CPU resources.
    * *Mitigation Response*: Rate limiting, followed by temporary blocking.
2.  **Persistent Malware Infection (`malware_attacker.py`)**: Infects a node, causing a permanent **+20% CPU overhead** on all message processing and attempting autonomous propagation (Worm Behaviour).
    * *Mitigation Response*: Immediate permanent JID block, quarantine advisory, and a probabilistic `CURE_INFECTION` command.
3.  **Escalating Insider Threat (`insider_attacker.py`)**: Simulates a trusted user with escalating phases: failed logins, data exfiltration (bandwidth overhead), and backdoor installation (lateral movement).
    * *Mitigation Response*: Account suspension (`SUSPEND_ACCESS`), access audit, and a probabilistic `FORENSIC_CLEAN` command (harder to remove at higher intensities).

---

## 🚀 Getting Started

### Prerequisites

You need a running **XMPP server** configured with an anonymous authentication mechanism (e.g., ejabberd or Openfire). This server acts as the communication bus for all **SPADE** agents.

### How to run a spade server

First start a virtual environment
1. py -m virtualenv spade_venv

Activate spade
2. .\spade_venv\Scripts\Activate

Run the server
3. spade run

Note: The file should be run in another terminal

### Installation

1.  Clone this repository.
2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Simulation

Execute the main environment script

```bash
python environment.py 