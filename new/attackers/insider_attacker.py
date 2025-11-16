"""
Insider Threat Attacker - Simulates malicious insider with escalating access attempts

ATTACK TYPE: Insider Threat
────────────────────────────────────────────────────────────────

WHAT IT DOES:
  • Gradual escalation over time (3 phases)
  • Phase 1: Failed login attempts (5 attempts)
  • Phase 2: Unauthorized access to sensitive data (5 attempts)
  • Phase 3: Persistent data exfiltration attempts
  • CPU load: phase × 8% (8% → 16% → 24%) for 5 seconds

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

import spade
from spade.agent import Agent
from spade.behaviour import PeriodicBehaviour
from spade.message import Message


def _log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [INSIDER] {msg}")


class InsiderAttacker(Agent):
    """Simulates insider threat with gradual escalation."""

    class InsiderBehaviour(PeriodicBehaviour):
        """Escalates from failed logins to data exfiltration."""

        async def on_start(self):
            _log(f"Starting insider threat attack from {self.agent.jid}")
            self.phase = 1
            self.attempt_count = 0
            _log("Phase 1: Attempting credential access...")

        async def run(self):
            targets = self.agent.get("targets") or []
            
            if not targets:
                return
            
            # Round-robin target selection
            target_index = self.agent.get("target_index") or 0
            target = targets[target_index % len(targets)]
            self.agent.set("target_index", (target_index + 1) % len(targets))
            
            # Escalate attack over time
            if self.attempt_count < 5:
                # Phase 1: Failed login attempts
                if self.phase != 1:
                    self.phase = 1
                    _log("Phase 1: Failed login attempts")
                msg_body = f"ATTACK: Failed login attempt for admin user (try #{self.attempt_count + 1})"
                phase = 1
            elif self.attempt_count < 10:
                # Phase 2: Unauthorized access attempts
                if self.phase != 2:
                    self.phase = 2
                    _log("[!] Phase 2: Escalating to unauthorized access attempts")
                msg_body = f"ATTACK: Attempting unauthorized access to sensitive data"
                phase = 2
            else:
                # Phase 3: Persistent breach attempt
                if self.phase != 3:
                    self.phase = 3
                    _log("[!!] Phase 3: Persistent data exfiltration attempts")
                msg_body = "ATTACK: Persistent unauthorized access attempt - trying data exfiltration"
                phase = 3

            try:
                # Extrai o JID do router a partir do JID do nó
                # (ex: "router1_node0@localhost" -> "router1" + "@" + "localhost")
                router_jid = target.split('_')[0] + "@" + target.split('@')[1]
            except Exception:
                _log(f"ERRO: Não foi possível extrair o router JID do target {target}")
                router_jid = target  # Fallback para o comportamento antigo se o nome for inesperado

                # A mensagem é enviada PARA O ROUTER, com o nó como destino final
            msg = Message(to=router_jid)
            msg.set_metadata("dst", target)
            msg.set_metadata("protocol", "attack")
            task_data = {
                "cpu_load": phase * 8.0,  # Escalating load: 8%, 16%, 24%
                "duration": 5.0
            }
            msg.set_metadata("task", json.dumps(task_data))
            msg.body = msg_body
            await self.send(msg)
            
            _log(f"→ {target}: Phase {phase} - {msg_body[:60]}...")
            
            self.attempt_count += 1
            
            # Check if duration expired
            start_time = self.agent.get("attack_start_time") or 0
            duration = self.agent.get("duration") or 40
            if asyncio.get_event_loop().time() - start_time > duration:
                _log(f"Attack duration expired after {self.attempt_count} attempts - stopping")
                self.kill()

    async def setup(self):
        _log(f"Insider threat attacker initialized: {self.jid}")
        
        # Store attack start time
        self.set("attack_start_time", asyncio.get_event_loop().time())
        
        # Start insider behavior (period = 3 seconds between attempts)
        behav = self.InsiderBehaviour(period=3.0)
        self.add_behaviour(behav)
        
        duration = int(self.get("duration") or 40)
        max_attempts = duration // 3
        _log(f"Attack duration: {duration}s (~{max_attempts} attempts)")
        _log("Escalation plan: 5 failed logins → 5 unauthorized access → persistent exfiltration")


async def main():
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