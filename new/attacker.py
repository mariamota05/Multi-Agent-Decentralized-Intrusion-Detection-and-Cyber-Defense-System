"""
Attacker Agent - Simulates malicious behavior

Implements three attack types with corresponding incident response strategies:

╔═══════════════════════════════════════════════════════════════════════════════╗
║ 1. STEALTH MALWARE ATTACK                                                    ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ Attack Characteristics:                                                       ║
║   - Low-volume periodic messages (stealth to avoid rate detection)           ║
║   - Contains malware keywords: trojan, virus, ransomware, worm               ║
║   - Attempts to install backdoors and propagate                              ║
║   - Moderate CPU load (intensity × 5%) over 3 seconds                        ║
║                                                                               ║
║ Why AGGRESSIVE CONTAINMENT Response? (3 steps)                               ║
║   1. Immediate Block (0.3s): Malware can SPREAD - speed is critical          ║
║      → Block attacker instantly before infection spreads to other nodes      ║
║                                                                               ║
║   2. Quarantine Advisory: Infected systems need ISOLATION                    ║
║      → Advisory sent to isolate potentially infected nodes from network      ║
║      → Prevents lateral movement if payload already delivered                ║
║                                                                               ║
║   3. Fast Response Time: Fastest of all strategies                           ║
║      → Every second counts - malware replicates/encrypts/exfiltrates fast    ║
║      → No investigation needed - malware keywords = definite threat          ║
║                                                                               ║
║ Risk: HIGH - Can compromise data, spread across network, permanent damage    ║
╚═══════════════════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════════════════╗
║ 2. DDoS ATTACK                                                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ Attack Characteristics:                                                       ║
║   - High-volume bursts (intensity × 10 messages per burst)                   ║
║   - 3 bursts total with 5-second intervals                                   ║
║   - Designed to overwhelm resources and cause service outage                 ║
║   - High CPU load (intensity × 3%) over 2-second bursts                      ║
║                                                                               ║
║ Why GRADUATED RESPONSE? (3 steps)                                            ║
║   1. Rate Limiting First (10 msg/s): DDoS is about VOLUME not CONTENT       ║
║      → Throttle traffic instead of blocking - might be legitimate burst      ║
║      → Allows some traffic through in case of false positive                 ║
║      → Less aggressive than full block - proportionate response              ║
║                                                                               ║
║   2. Temporary Block (30s): Escalate only if rate limit insufficient         ║
║      → Short block gives time for flood to subside                           ║
║      → Temporary because source IP might be spoofed/botnet                   ║
║      → Can reassess after timeout - maybe attack stopped                     ║
║                                                                               ║
║   3. Monitoring Scheduled: DDoS often comes in WAVES                         ║
║      → Watch for sustained attack patterns                                   ║
║      → Detect if it's part of larger distributed attack                      ║
║      → Gather intelligence for upstream filtering                            ║
║                                                                               ║
║ Risk: MEDIUM - Causes service disruption but no data loss/system compromise  ║
╚═══════════════════════════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════════════════════════╗
║ 3. INSIDER THREAT ATTACK                                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ Attack Characteristics:                                                       ║
║   - Gradual escalation over time (3 phases)                                  ║
║   - Phase 1: Failed login attempts (5 attempts)                              ║
║   - Phase 2: Unauthorized access attempts (5 attempts)                       ║
║   - Phase 3: Data exfiltration attempts (persistent)                         ║
║   - Escalating CPU load (phase × 8%: 8%, 16%, 24%) over 5 seconds            ║
║                                                                               ║
║ Why INVESTIGATIVE APPROACH? (4 steps)                                        ║
║   1. Account Suspension (soft block): Insider has LEGITIMATE ACCESS          ║
║      → Could be compromised account, not malicious user                      ║
║      → Reversible action in case of false positive/credential theft          ║
║      → Don't burn bridges - might be confused employee                       ║
║                                                                               ║
║   2. Access Audit Initiated: Need to know WHAT WAS ACCESSED                  ║
║      → Insider already has credentials - what did they see?                  ║
║      → Log analysis reveals scope of breach                                  ║
║      → Identify if data was exfiltrated or just viewed                       ║
║                                                                               ║
║   3. Administrator Alerts: Requires HUMAN JUDGMENT                           ║
║      → Could be legitimate user with misconfigured permissions               ║
║      → HR/legal implications - can't auto-ban employees                      ║
║      → Context matters - security team needs to investigate motive           ║
║                                                                               ║
║   4. Permanent Block After Investigation: ONLY if confirmed malicious        ║
║      → Investigation takes time - longest response (0.7s)                    ║
║      → Must balance security with false positives                            ║
║      → Permanent only after confirming malicious intent                      ║
║                                                                               ║
║ Risk: HIGH (but different) - Has valid credentials, knows systems, trusted   ║
║       Damage often discovered late, difficult to detect, requires forensics  ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Configuration:
 - attack_type: Which attack to perform (stealth_malware, ddos, insider_threat)
 - targets: List of JIDs to attack
 - intensity: How aggressive the attack is (1-10)
 - duration: How long to attack (seconds)
 - stealth_mode: If true, tries to evade detection
"""

import argparse
import asyncio
import datetime
import getpass
from itertools import cycle
from typing import List

import spade
from spade.agent import Agent
from spade.behaviour import PeriodicBehaviour, CyclicBehaviour
from spade.message import Message


def _log(agent_type: str, jid: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class AttackerAgent(Agent):
    """
    Malicious agent that performs various types of attacks.
    
    Stores:
      - attack_type: Type of attack to perform
      - targets: List of target JIDs
      - intensity: Attack intensity (1-10)
      - duration: Attack duration in seconds
      - stealth_mode: Whether to try evading detection
    """

    class StealthMalwareBehaviour(PeriodicBehaviour):
        """
        Sends periodic low-volume malicious messages.
        Uses keywords that monitoring should detect, but slowly to avoid rate limits.
        """

        async def on_start(self):
            _log("Attacker", str(self.agent.jid), "Starting stealth malware attack...")

        async def run(self):
            targets = self.agent.get("targets") or []
            intensity = int(self.agent.get("intensity") or 3)
            
            if not targets:
                return
            
            # Round-robin target selection instead of random
            target_index = self.agent.get("stealth_target_index") or 0
            target = targets[target_index % len(targets)]
            self.agent.set("stealth_target_index", (target_index + 1) % len(targets))
            
            # Craft malicious message with suspicious keywords
            # These are ATTACK ATTEMPTS - firewall should detect and block them
            malware_messages = [
                "ATTACK: Attempting to install trojan backdoor",
                "ATTACK: Trying to inject malware payload",
                "ATTACK: Attempting virus propagation",
                "ATTACK: Trying to deploy ransomware",
                "ATTACK: Attempting worm replication",
                "ATTACK: Trying to exploit system vulnerability"
            ]
            
            # Cycle through messages instead of random
            msg_index = self.agent.get("malware_msg_index") or 0
            msg_body = malware_messages[msg_index % len(malware_messages)]
            self.agent.set("malware_msg_index", (msg_index + 1) % len(malware_messages))
            
            # Send message with resource load
            msg = Message(to=target)
            msg.set_metadata("protocol", "attack")
            # Add task metadata to consume target resources
            import json
            task_data = {
                "cpu_load": intensity * 5.0,  # CPU load based on intensity
                "duration": 3.0  # Task lasts 3 seconds
            }
            msg.set_metadata("task", json.dumps(task_data))
            msg.body = msg_body
            await self.send(msg)
            
            _log("Attacker", str(self.agent.jid), f"Sent malware message to {target}: {msg_body[:30]}...")
            
            # Check if duration expired
            start_time = self.agent.get("attack_start_time") or 0
            duration = self.agent.get("duration") or 30
            if asyncio.get_event_loop().time() - start_time > duration:
                _log("Attacker", str(self.agent.jid), "Stealth malware attack duration expired")
                self.kill()

    class DDoSBehaviour(CyclicBehaviour):
        """
        Sends sudden bursts of messages to overwhelm targets.
        High volume spike that should trigger rate-based detection.
        """

        async def on_start(self):
            _log("Attacker", str(self.agent.jid), "Starting DDoS attack...")
            self.burst_count = 0
            self.max_bursts = 3

        async def run(self):
            targets = self.agent.get("targets") or []
            intensity = int(self.agent.get("intensity") or 5)
            
            if not targets or self.burst_count >= self.max_bursts:
                if self.burst_count >= self.max_bursts:
                    _log("Attacker", str(self.agent.jid), "DDoS attack completed")
                    self.kill()
                return
            
            # Send burst of messages
            burst_size = intensity * 10
            _log("Attacker", str(self.agent.jid), f"Sending DDoS burst #{self.burst_count + 1} ({burst_size} messages)...")
            
            target_index = self.agent.get("ddos_target_index") or 0
            import json
            for i in range(burst_size):
                target = targets[target_index % len(targets)]
                target_index += 1
                msg = Message(to=target)
                msg.set_metadata("protocol", "attack")
                # DDoS causes high CPU load
                task_data = {
                    "cpu_load": intensity * 3.0,  # High CPU load
                    "duration": 2.0  # Short bursts
                }
                msg.set_metadata("task", json.dumps(task_data))
                msg.body = f"ATTACK: DDoS flood packet {i} - attempting to overwhelm target"
                await self.send(msg)
                
                # Small delay to not overwhelm local system
                await asyncio.sleep(0.01)
            
            self.agent.set("ddos_target_index", target_index % len(targets))
            
            self.burst_count += 1
            _log("Attacker", str(self.agent.jid), f"DDoS burst #{self.burst_count} sent ({burst_size} messages)")
            
            # Wait before next burst
            await asyncio.sleep(5.0)

    class InsiderThreatBehaviour(PeriodicBehaviour):
        """
        Simulates insider threat with gradual escalation.
        Starts with failed logins, escalates to unauthorized access attempts.
        """

        async def on_start(self):
            _log("Attacker", str(self.agent.jid), "Starting insider threat attack...")
            self.phase = 1
            self.attempt_count = 0

        async def run(self):
            targets = self.agent.get("targets") or []
            
            if not targets:
                return
            
            # Round-robin target selection
            target_index = self.agent.get("insider_target_index") or 0
            target = targets[target_index % len(targets)]
            self.agent.set("insider_target_index", (target_index + 1) % len(targets))
            
            # Escalate attack over time
            if self.attempt_count < 5:
                # Phase 1: Failed login attempts
                msg_body = f"ATTACK: Failed login attempt for admin user (try #{self.attempt_count + 1})"
                self.phase = 1
            elif self.attempt_count < 10:
                # Phase 2: Unauthorized access attempts
                msg_body = f"ATTACK: Attempting unauthorized access to sensitive data"
                self.phase = 2
            else:
                # Phase 3: Persistent breach attempt
                msg_body = "ATTACK: Persistent unauthorized access attempt - trying data exfiltration"
                self.phase = 3
            
            msg = Message(to=target)
            msg.set_metadata("protocol", "attack")
            # Insider threat load increases with phase
            import json
            task_data = {
                "cpu_load": self.phase * 8.0,  # Escalating load (8%, 16%, 24%)
                "duration": 5.0  # Longer duration
            }
            msg.set_metadata("task", json.dumps(task_data))
            msg.body = msg_body
            await self.send(msg)
            
            _log("Attacker", str(self.agent.jid), 
                 f"Insider threat phase {self.phase}: {msg_body[:40]}...")
            
            self.attempt_count += 1
            
            # Check if duration expired
            start_time = self.agent.get("attack_start_time") or 0
            duration = self.agent.get("duration") or 60
            if asyncio.get_event_loop().time() - start_time > duration:
                _log("Attacker", str(self.agent.jid), "Insider threat attack duration expired")
                self.kill()

    async def setup(self):
        _log("Attacker", str(self.jid), "starting...")
        
        attack_type = self.get("attack_type") or "stealth_malware"
        intensity = int(self.get("intensity") or 5)
        
        # Record attack start time
        self.set("attack_start_time", asyncio.get_event_loop().time())
        
        # Start appropriate attack behaviour
        if attack_type == "stealth_malware":
            # Periodic, slow attack
            period = max(2.0, 10.0 / intensity)  # More intense = more frequent
            behav = self.StealthMalwareBehaviour(period=period)
            self.add_behaviour(behav)
            _log("Attacker", str(self.jid), f"Launched stealth malware attack (period={period:.1f}s)")
            
        elif attack_type == "ddos":
            # Burst attack
            behav = self.DDoSBehaviour()
            self.add_behaviour(behav)
            _log("Attacker", str(self.jid), f"Launched DDoS attack (intensity={intensity})")
            
        elif attack_type == "insider_threat":
            # Gradual escalation
            period = max(1.0, 5.0 / intensity)
            behav = self.InsiderThreatBehaviour(period=period)
            self.add_behaviour(behav)
            _log("Attacker", str(self.jid), f"Launched insider threat attack (period={period:.1f}s)")
        
        else:
            _log("Attacker", str(self.jid), f"Unknown attack type: {attack_type}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Attacker agent JID")
    parser.add_argument("--password", required=False, help="Agent password; if omitted you'll be prompted")
    parser.add_argument("--targets", required=True, help="Comma-separated target JIDs to attack")
    parser.add_argument("--attack-type", default="stealth_malware", 
                        choices=["stealth_malware", "ddos", "insider_threat"],
                        help="Type of attack to perform")
    parser.add_argument("--intensity", type=int, default=5, 
                        help="Attack intensity (1-10, higher = more aggressive)")
    parser.add_argument("--duration", type=int, default=30, 
                        help="Attack duration in seconds")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass()
    targets = [t.strip() for t in args.targets.split(',') if t.strip()]

    agent = AttackerAgent(args.jid, passwd)
    agent.set("targets", targets)
    agent.set("attack_type", args.attack_type)
    agent.set("intensity", args.intensity)
    agent.set("duration", args.duration)

    try:
        await agent.start(auto_register=True)
    except Exception as e:
        _log("Attacker", args.jid, f"Failed to start: {e}")
        return

    _log("Attacker", args.jid, f"running {args.attack_type} attack for {args.duration}s. Press Ctrl+C to stop")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        _log("Attacker", args.jid, "Stopping...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    spade.run(main())
