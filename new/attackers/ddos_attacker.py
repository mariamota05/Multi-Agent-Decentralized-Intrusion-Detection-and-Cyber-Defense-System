"""
DDoS Attacker - Floods targets with high-volume traffic

ATTACK TYPE: Distributed Denial of Service
────────────────────────────────────────────────────────────────

WHAT IT DOES:
  • Sends sudden bursts of messages to overwhelm targets
  • 3 bursts total with 5-second intervals between them
  • Burst size: intensity × 10 messages
  • CPU load: intensity × 3% for 2 seconds per message

WHY THIS RESPONSE?
  ✓ Rate limiting first (10 msg/s) - proportionate response
  ✓ Temporary 30s block - gives time for flood to subside
  ✓ Monitoring scheduled - watch for sustained patterns
  ✓ Not permanent - source might be spoofed/botnet

RISK LEVEL: ⚠️ MEDIUM
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
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [💥 DDoS] {msg}")


class DDoSAttacker(Agent):
    """Sends high-volume bursts to overwhelm targets."""

    class DDoSBehaviour(CyclicBehaviour):
        """Sends bursts of messages to cause service disruption."""

        async def on_start(self):
            _log(f"Starting DDoS attack from {self.agent.jid}")
            self.burst_count = 0
            self.max_bursts = 3

        async def run(self):
            targets = self.agent.get("targets") or []
            intensity = int(self.agent.get("intensity") or 5)
            
            if not targets or self.burst_count >= self.max_bursts:
                if self.burst_count >= self.max_bursts:
                    _log(f"Completed {self.max_bursts} bursts - attack finished")
                    self.kill()
                return
            
            # Calculate burst size based on intensity
            burst_size = intensity * 10
            _log(f"🌊 BURST #{self.burst_count + 1}/{self.max_bursts} - Sending {burst_size} messages...")
            
            # Round-robin through targets
            target_index = self.agent.get("target_index") or 0
            
            for i in range(burst_size):
                target = targets[target_index % len(targets)]
                target_index += 1
                
                msg = Message(to=target)
                msg.set_metadata("protocol", "attack")
                task_data = {
                    "cpu_load": intensity * 3.0,  # High CPU load
                    "duration": 2.0
                }
                msg.set_metadata("task", json.dumps(task_data))
                msg.body = f"ATTACK: DDoS flood packet {i+1}/{burst_size} - attempting to overwhelm target"
                await self.send(msg)
                
                # Small delay to not overwhelm local system
                await asyncio.sleep(0.01)
            
            self.agent.set("target_index", target_index % len(targets))
            
            self.burst_count += 1
            _log(f"✓ Burst #{self.burst_count} complete ({burst_size} messages sent)")
            
            if self.burst_count < self.max_bursts:
                _log(f"⏸️  Waiting 5 seconds before next burst...")
                await asyncio.sleep(5.0)

    async def setup(self):
        _log(f"DDoS attacker initialized: {self.jid}")
        
        # Start DDoS behavior
        behav = self.DDoSBehaviour()
        self.add_behaviour(behav)
        
        intensity = int(self.get("intensity") or 5)
        burst_size = intensity * 10
        total_messages = burst_size * 3
        _log(f"Attack plan: 3 bursts × {burst_size} messages = {total_messages} total")


async def main():
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
