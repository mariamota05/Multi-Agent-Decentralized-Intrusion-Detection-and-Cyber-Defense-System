# confirma ataques


"""
Monitoring agent for the simulated network.

This agent listens for messages and applies simple heuristics to detect
potentially malicious traffic. On detection it can:
 - send an alert to an incident response agent (if configured)
 - optionally instruct node firewalls to block an offending JID by sending
   a 'firewall-control' message to configured node JIDs

Heuristics implemented:
 - Keyword blacklist scanning
 - Rate-based detection for repeated suspicious messages (e.g., repeated failed login)

Usage example:
  python new/monitoring.py --jid monitor@localhost --password secret --nodes node1@localhost,node2@localhost --response response@localhost --auto-block

Notes:
 - SPADE and a running XMPP server are required.
 - Nodes should forward or send copies of traffic to the monitor JID for it to inspect
   (in this simple simulation the other agents can include the monitor in their peers list).
"""

import argparse
import asyncio
import datetime
import getpass
from collections import defaultdict, deque
from typing import Deque

import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message


class MonitoringAgent(Agent):
    """Agent that monitors messages and generates alerts.

    Key configuration stored in agent attributes:
      - nodes_to_notify: list of node JIDs whose firewalls will be instructed to block
      - response_jid: JID of incident response agent to receive alerts
      - auto_block: if True, send firewall-control BLOCK_JID messages to nodes_to_notify
    """

    class MonitorBehav(CyclicBehaviour):
        def __init__(self, suspicious_window: int = 10, suspicious_threshold: int = 5, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # time window (seconds) for rate-based detection
            self.window = suspicious_window
            # number of suspicious events from same sender within window to raise alert
            self.threshold = suspicious_threshold
            # map sender -> timestamps deque
            self.events: dict[str, Deque[float]] = defaultdict(lambda: deque())
            # keyword blacklist
            self.keywords = [
                "malware",
                "virus",
                "exploit",
                "attack",
                "trojan",
                "worm",
                "ransomware",
                "failed login",
                "failed_login",
                "unauthorized",
            ]

        async def on_start(self):
            print(f"[MonitoringAgent {self.agent.jid}] Monitoring behaviour started")

        async def process_message(self, msg: Message):
            now = asyncio.get_event_loop().time()
            sender = str(msg.sender) if msg.sender else "unknown"
            body = (msg.body or "").lower()

            # Informational log: monitoring check started
            now_ts = datetime.datetime.now().time()
            print(f"[{now_ts}] [MonitoringAgent {self.agent.jid}] Checking message from {sender}")

            suspicious = False
            reasons = []

            # keyword scanning
            for kw in self.keywords:
                if kw in body:
                    suspicious = True
                    reasons.append(f"keyword:{kw}")

            # simple heuristics: repeated failed login keywords
            if "failed" in body and ("login" in body or "auth" in body):
                # record event timestamp
                dq = self.events[sender]
                dq.append(now)
                # purge old events
                while dq and dq[0] < now - self.window:
                    dq.popleft()
                if len(dq) >= self.threshold:
                    suspicious = True
                    reasons.append(f"rate:{len(dq)} in {self.window}s")

            if suspicious:
                ts = datetime.datetime.now().isoformat()
                alert = {
                    "time": ts,
                    "sender": sender,
                    "body": msg.body,
                    "reasons": reasons,
                }
                print(f"[{ts}] [MonitoringAgent {self.agent.jid}] [ALERT] {alert}")
                # notify response agent if available
                resp_jid = self.agent.get("response_jid")
                if resp_jid:
                    m = Message(to=resp_jid)
                    m.set_metadata("protocol", "monitoring-alert")
                    m.body = f"ALERT {alert}"
                    await self.send(m)
                    print(f"[{datetime.datetime.now().time()}] [MonitoringAgent {self.agent.jid}] Sent alert to response agent {resp_jid}")

                # auto-block offenders via firewall-control messages to nodes
                if self.agent.get("auto_block"):
                    offender = sender
                    nodes = self.agent.get("nodes_to_notify") or []
                    for node in nodes:
                        ctrl = Message(to=node)
                        ctrl.set_metadata("protocol", "firewall-control")
                        ctrl.body = f"BLOCK_JID:{offender}"
                        await self.send(ctrl)
                        print(f"[{datetime.datetime.now().time()}] [MonitoringAgent {self.agent.jid}] Sent firewall-control BLOCK_JID for {offender} to {node}")

            # Informational log: monitoring check completed (always log result)
            now_ts2 = datetime.datetime.now().time()
            print(f"[{now_ts2}] [MonitoringAgent {self.agent.jid}] Check completed for {sender}. Suspicious={suspicious}. Reasons={reasons}")

        async def run(self):
            msg = await self.receive(timeout=1)
            if msg:
                # handle monitoring of the message
                try:
                    await self.process_message(msg)
                except Exception as e:
                    print(f"Error processing message: {e}")

    async def setup(self):
        print(f"[MonitoringAgent {str(self.jid)}] starting...")
        b = self.MonitorBehav()
        self.add_behaviour(b)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Monitoring agent JID")
    parser.add_argument("--password", required=False, help="Agent password; if omitted you'll be prompted")
    parser.add_argument("--nodes", default="", help="Comma-separated node JIDs to instruct for blocking (optional)")
    parser.add_argument("--response", default="", help="Incident response agent JID to receive alerts (optional)")
    parser.add_argument("--auto-block", action="store_true", help="If set, send BLOCK_JID commands to nodes on detections")
    parser.add_argument("--window", type=int, default=10, help="Time window in seconds for rate detection")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold count within window to trigger rate alert")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass()
    nodes = [p.strip() for p in args.nodes.split(',') if p.strip()]

    agent = MonitoringAgent(args.jid, passwd)
    agent.set("nodes_to_notify", nodes)
    agent.set("response_jid", args.response if args.response else None)
    agent.set("auto_block", bool(args.auto_block))

    try:
        await agent.start(auto_register=True)
    except Exception as e:
        print(f"Failed to start MonitoringAgent {args.jid}: {e}")
        return

    # Configure the monitoring behaviour thresholds if provided
    # (behaviour created in setup; find and adjust)
    for b in agent.behaviours.values():
        if isinstance(b, MonitoringAgent.MonitorBehav):
            b.window = args.window
            b.threshold = args.threshold

    print("MonitoringAgent running. Press Ctrl+C to stop.")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        print("Stopping MonitoringAgent...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    spade.run(main())


