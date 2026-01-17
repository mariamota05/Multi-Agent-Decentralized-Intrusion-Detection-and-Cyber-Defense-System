"""
DDoS Attacker - Floods targets with high-volume traffic

ATTACK TYPE: Distributed Denial of Service
────────────────────────────────────────────────────────────────

WHAT IT DOES:
  • Sends sudden bursts of messages to overwhelm targets
  • 3 bursts total with 5-second intervals between them
  • Burst size: intensity x 10 messages
  • CPU load: intensity x 3% for 2 seconds per message

WHY THIS RESPONSE?
  [+] Rate limiting first (10 msg/s) - proportionate response
  [+] Temporary 30s block - gives time for flood to subside
  [+] Monitoring scheduled - watch for sustained patterns
  [+] Not permanent - source might be spoofed/botnet

RISK LEVEL: [!] MEDIUM
  - Causes service disruption and resource exhaustion
  - No data loss or system compromise
  - Can be mitigated with rate limiting
────────────────────────────────────────────────────────────────

Usage:
  python attackers/ddos_attacker.py --jid attacker@localhost --password secret \\
         --targets node1@localhost,node2@localhost --intensity 8
"""

import argparse
import asyncio
import datetime
import getpass
import json

import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message


def _log(msg: str) -> None:
    """Log helper for attacker script with timestamp.

    Args:
        msg (str): The message to display.
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [DDOS] {msg}")


class DDoSAttacker(Agent):
    """Sends high-volume bursts to overwhelm targets."""

    class DDoSBehaviour(CyclicBehaviour):
        """Sends bursts of messages to cause service disruption."""

        async def on_start(self):
            """Initializes burst count and maximum bursts upon starting the behavior."""
            _log(f"Starting DDoS attack from {self.agent.jid}")
            self.burst_count = 0
            self.max_bursts = 3
            # Initialize target index to 0 for round-robin targeting
            self.agent.set("target_index", 0)

        async def run(self):
            """Executes a single burst of DDoS messages against the configured targets."""
            targets = self.agent.get("targets") or []
            intensity = int(self.agent.get("intensity") or 5)

            if not targets or self.burst_count >= self.max_bursts:
                if self.burst_count >= self.max_bursts:
                    _log(f"Completed {self.max_bursts} bursts - attack finished")
                    # Stop the agent after all bursts are completed
                    self.kill()
                return

            # Calculate burst size based on intensity
            burst_size = intensity * 10
            _log(f"BURST #{self.burst_count + 1}/{self.max_bursts} - Sending {burst_size} messages...")

            # Round-robin through targets
            target_index = self.agent.get("target_index") or 0

            for i in range(burst_size):
                target_node_jid = targets[target_index % len(targets)]
                target_index += 1

                try:
                    # Messages must be sent to the target's parent router first
                    router_name = target_node_jid.split('_')[0]
                    domain = target_node_jid.split('@')[1]
                    target_router_jid = f"{router_name}@{domain}"
                except Exception:
                    _log(f"Erro: Não consegui extrair o JID do router de {target_node_jid}. A enviar diretamente.")
                    target_router_jid = target_node_jid


                msg = Message(to=target_router_jid)

                # Set original destination node JID in metadata
                msg.set_metadata("dst", target_node_jid)
                msg.set_metadata("attacker_intensity", str(intensity))  # Pass intensity for detection

                msg.set_metadata("protocol", "attack")
                # Define CPU load task for the target node
                task_data = {
                    "cpu_load": intensity * 3.0,  # High CPU load (3% per intensity point)
                    "duration": 2.0
                 }
                msg.set_metadata("task", json.dumps(task_data))
                msg.body = f"REQUEST:{i + 1}/{burst_size}"

                await self.send(msg)
                # Small delay to simulate high-volume sending without overwhelming the platform queue
                await asyncio.sleep(0.01)

            # Update the index for the next burst
            self.agent.set("target_index", target_index % len(targets))

            self.burst_count += 1
            _log(f"[+] Burst #{self.burst_count} complete ({burst_size} messages sent)")

            if self.burst_count < self.max_bursts:
                _log(f"Waiting 5 seconds before next burst...")
                await asyncio.sleep(5.0)

    async def setup(self):
        """Sets up the DDoSAttacker by adding the DDoSBehaviour."""
        _log(f"DDoS attacker initialized: {self.jid}")

        # Start DDoS behavior
        behav = self.DDoSBehaviour()
        self.add_behaviour(behav)

        intensity = int(self.get("intensity") or 5)
        burst_size = intensity * 10
        total_messages = burst_size * 3
        _log(f"Attack plan: 3 bursts x {burst_size} messages = {total_messages} total")


async def main():
    """Parses command line arguments, initializes the DDoSAttacker agent, and runs the simulation."""
    parser = argparse.ArgumentParser(description="DDoS Attacker - Floods targets with traffic")
    parser.add_argument("--jid", required=True, help="Attacker JID (e.g., attacker@localhost)")
    parser.add_argument("--password", help="Password (prompted if not provided)")
    parser.add_argument("--targets", required=True, help="Comma-separated target JIDs")
    parser.add_argument("--intensity", type=int, default=5, help="Attack intensity 1-10 (default: 5)")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass(f"Password for {args.jid}: ")
    targets = [t.strip() for t in args.targets.split(',') if t.strip()]

    agent = DDoSAttacker(args.jid, passwd)
    agent.set("targets", targets)
    agent.set("intensity", args.intensity)

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