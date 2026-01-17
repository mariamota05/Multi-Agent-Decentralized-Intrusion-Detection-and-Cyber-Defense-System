"""
Insider Threat Attacker - Simulates malicious insider with escalating access attempts

ATTACK TYPE: Insider Threat
────────────────────────────────────────────────────────────────

WHAT IT DOES:
  • Gradual escalation over time (3 phases)
  • Phase 1: Failed login attempts (5 attempts)
  • Phase 2: Unauthorized access to sensitive data (5 attempts)
  • Phase 3: Persistent data exfiltration attempts
  • CPU load: phase x 8% (8% -> 16% -> 24%) for 5 seconds

WHY THIS RESPONSE?
  [+] Account suspension first - reversible soft block
  [+] Access audit - log what was accessed/exfiltrated
  [+] Admin alerts - human review required
  [+] Permanent block only after investigation

RISK LEVEL: [!] HIGH
  - Has valid credentials and knows systems
  - Trusted user makes detection difficult
  - Can access sensitive data before detection
  - Requires forensic investigation
────────────────────────────────────────────────────────────────

Usage:
  python attackers/insider_attacker.py --jid attacker@localhost --password secret \\
         --targets node1@localhost,node2@localhost --intensity 6 --duration 40
"""

import argparse
import asyncio
import datetime
import getpass
import json
import random
import spade
from spade.agent import Agent
from spade.behaviour import PeriodicBehaviour
from spade.message import Message


def _log(msg: str) -> None:
    """Log helper for attacker script with timestamp.

    Args:
        msg (str): The message to display.
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [INSIDER] {msg}")


class InsiderAttacker(Agent):
    """Simulates insider threat with gradual escalation."""

    class InsiderBehaviour(PeriodicBehaviour):
        """Escalates from failed logins to data exfiltration."""

        async def on_start(self):
            """Initializes the attack state, setting the starting phase and attempt count."""
            _log(f"Starting insider threat attack from {self.agent.jid}")
            self.phase = 1
            self.attempt_count = 0
            self.blocked = False  # Track if attacker was blocked
            _log("Phase 1: Attempting credential access...")

        async def run(self):
            """Executes a single periodic attack attempt, handles counter-measures, and escalates the phase."""
            # Check if attacker was blocked
            if self.blocked:
                return

            targets = self.agent.get("targets") or []
            intensity = self.agent.get("intensity") or 6

            if not targets:
                return

            # Round-robin target selection
            target_index = self.agent.get("target_index") or 0
            target = targets[target_index % len(targets)]
            self.agent.set("target_index", (target_index + 1) % len(targets))

            try:
                # Messages must be sent to the target's parent router first
                router_jid = target.split('_')[0] + "@" + target.split('@')[1]
            except Exception:
                _log(f"ERROR: Could not extract router JID from target {target}")
                router_jid = target

            # Check for ALL incoming messages (account suspension/blocking)
            # Drain the inbox to prevent race conditions between phases
            while True:
                msg = await self.receive(timeout=0.1)  # Non-blocking check
                if not msg:
                    break  # No more messages in queue

                body = msg.body.lower()
                if "suspend" in body or "block" in body or "ban" in body:
                    # High-intensity attackers (7+) may ignore bans (APT behavior)
                    # Low-intensity attackers always stop when caught
                    if intensity <= 7:
                        _log(f"[!] ATTACK STOPPED: Account suspended/blocked - {msg.body}")
                        self.blocked = True
                        self.kill()
                        return
                    else:
                        if "repeated" in body:
                            if "severe" in body: #3
                                if intensity <= 9:
                                    _log(f"[!] ATTACK STOPPED: Repeated bans - {msg.body}")
                                    self.blocked = True
                                    self.kill()
                                    return
                                else: #maximum intensity
                                    bit = random.randint(0, 1)
                                    if bit == 0:
                                        _log(f"[!!!] HIGH-INTENSITY ATTACKER IGNORES BAN AGAIN: Continuing attack despite {msg.body}")
                                    else:
                                        _log(f"[!] ATTACK FINALLY STOPPED: Repeated bans - {msg.body}")
                                        self.blocked = True
                                        self.kill()
                                        return

                            else: #2
                                if intensity >= 9:
                                    _log(f"[!!] HIGH-INTENSITY ATTACKER IGNORES BAN: Continuing attack despite {msg.body}")
                                else:
                                    _log(f"[!] ATTACK STOPPED: Repeated bans - {msg.body}")
                                    self.blocked = True
                                    self.kill()
                                    return
                        else:
                            #como é o primeiro ataque deixamos passar
                            _log(f"Detected and banned, but continuing attack with evasion techniques, despite {msg.body}")

            # Phase escalation logic
            if self.attempt_count < 5:
                # Phase 1: Failed login attempts (passive probing)
                if self.phase != 1:
                    self.phase = 1
                    _log("Phase 1: Failed login attempts (probing)")

                msg = Message(to=router_jid)
                msg.set_metadata("dst", target)
                msg.set_metadata("protocol", "attack")
                msg.set_metadata("attacker_intensity", str(intensity))
                msg.set_metadata("original_sender", str(self.agent.jid))
                # CPU Load: 8.0%
                task_data = {"cpu_load": 8.0, "duration": 5.0}
                msg.set_metadata("task", json.dumps(task_data))
                msg.body = f"ATTACK: Failed login attempt for admin user (try #{self.attempt_count + 1}) on TARGET:{target}"
                await self.send(msg)
                phase = 1

            elif self.attempt_count < 10:
                # Phase 2: Data Exfiltration (REACTIVE - bandwidth overhead!)
                if self.phase != 2:
                    self.phase = 2
                    _log(f"[!] Phase 2: DATA EXFILTRATION (intensity={intensity} -> +{intensity*5}% bandwidth)")

                msg = Message(to=router_jid)
                msg.set_metadata("dst", target)
                msg.set_metadata("protocol", "attack")
                msg.set_metadata("attacker_intensity", str(intensity))
                msg.set_metadata("original_sender", str(self.agent.jid))
                # CPU Load is derived by node/router, here we just set the intent
                msg.body = f"DATA_EXFILTRATION:sensitive_data (intensity={intensity}) TARGET:{target}"
                await self.send(msg)
                phase = 2

            else:
                # Phase 3: Backdoor Installation (REACTIVE - lateral movement!)
                if self.phase != 3:
                    self.phase = 3
                    _log(f"[!!] Phase 3: BACKDOOR INSTALLATION (intensity={intensity} -> lateral spread enabled)")

                msg = Message(to=router_jid)
                msg.set_metadata("dst", target)
                msg.set_metadata("protocol", "attack")
                msg.set_metadata("attacker_intensity", str(intensity))
                msg.set_metadata("original_sender", str(self.agent.jid))
                # CPU Load is derived by node/router, here we just set the intent
                msg.body = f"BACKDOOR_INSTALL:insider_backdoor (intensity={intensity}) TARGET:{target}"
                await self.send(msg)
                phase = 3

            _log(f"-> {target}: Phase {phase} - attempt #{self.attempt_count + 1}")

            self.attempt_count += 1

            # Check if duration expired
            start_time = self.agent.get("attack_start_time") or 0
            duration = self.agent.get("duration") or 40
            if asyncio.get_event_loop().time() - start_time > duration:
                _log(f"Attack duration expired after {self.attempt_count} attempts - stopping")
                self.kill()

    async def setup(self):
        """Sets up the InsiderAttacker by storing the start time and adding the InsiderBehaviour."""
        _log(f"Insider threat attacker initialized: {self.jid}")

        # Store attack start time
        self.set("attack_start_time", asyncio.get_event_loop().time())

        # Start insider behavior (period = 3 seconds between attempts)
        behav = self.InsiderBehaviour(period=3.0)
        self.add_behaviour(behav)

        duration = int(self.get("duration") or 40)
        max_attempts = duration // 3
        _log(f"Attack duration: {duration}s (~{max_attempts} attempts)")
        _log("Escalation plan: 5 failed logins -> 5 unauthorized access -> persistent exfiltration")


async def main():
    """Parses command line arguments, initializes the InsiderAttacker agent, and runs the simulation."""
    parser = argparse.ArgumentParser(description="Insider Threat Attacker - Escalating access attempts")
    parser.add_argument("--jid", required=True, help="Attacker JID (e.g., attacker@localhost)")
    parser.add_argument("--password", help="Password (prompted if not provided)")
    parser.add_argument("--targets", required=True, help="Comma-separated target JIDs")
    parser.add_argument("--intensity", type=int, default=6, help="Attack intensity 1-10 (default: 6)")
    parser.add_argument("--duration", type=int, default=40, help="Attack duration in seconds (default: 40)")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass(f"Password for {args.jid}: ")
    targets = [t.strip() for t in args.targets.split(',') if t.strip()]

    agent = InsiderAttacker(args.jid, passwd)
    agent.set("targets", targets)
    agent.set("intensity", args.intensity)
    agent.set("duration", args.duration)

    try:
        await agent.start(auto_register=True)
        _log(f"Agent started - targeting {len(targets)} nodes")
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        _log("Stopping attack...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    spade.run(main())