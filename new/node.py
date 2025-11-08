"""
Simple workstation/server node using SPADE.

This NodeAgent acts like a workstation or server: it listens for messages and
responds to requests. It can also optionally send periodic heartbeats to a list
of peers, and supports an interactive mode to send manual messages.

Usage:
 - run the script and provide the agent JID and password
 - provide a comma-separated list of peer JIDs (optional)
 - set a heartbeat interval (seconds) or 0 to disable
 - choose interactive mode to type messages to send

Notes:
 - SPADE does not provide an XMPP server. You must have an XMPP server running
   (Prosody, ejabberd or public service) and the agent accounts registered there.
 - The agent will attempt auto_register=True; if the server does not allow in-band
   registration, create accounts on the server instead.
"""

import argparse
import asyncio
import datetime
import getpass

import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour, PeriodicBehaviour
from spade.message import Message
from firewall import FirewallBehaviour


# Note: the user requested no XMPP server probe. SPADE is expected to be
# available and a running XMPP server (or service) with accounts configured.


class NodeAgent(Agent):
    """An agent that listens and responds to messages and can send heartbeats.

    Behaviours:
      - RecvBehav: waits for messages and handles simple commands:
            * 'PING' -> replies 'PONG'
            * 'REQUEST:<text>' -> replies 'RESPONSE:<text processed>'
      - HeartbeatBehav: periodically sends 'HEARTBEAT' messages to configured peers.
    """

    class RecvBehav(CyclicBehaviour):
        async def run(self):
            msg = await self.receive(timeout=10)
            if msg:
                # Check firewall (if present) for inbound messages
                fw = None
                try:
                    fw = self.agent.get("firewall")
                except Exception:
                    fw = None
                if fw:
                    allowed = await fw.allow_message(msg)
                    if not allowed:
                        print(f"Firewall blocked inbound message from {msg.sender}")
                        return
                now = datetime.datetime.now().time()
                print(f"[{now}] Received from {msg.sender}: {msg.body}")

                # simple protocol handling
                body = (msg.body or "").strip()
                if body.upper() == "PING":
                    reply = Message(to=str(msg.sender))
                    reply.body = "PONG"
                    await self.send(reply)
                    print(f"Sent PONG to {msg.sender}")
                elif body.startswith("REQUEST:"):
                    content = body.split("REQUEST:", 1)[1]
                    reply = Message(to=str(msg.sender))
                    reply.body = f"RESPONSE: processed '{content.strip()}'"
                    await self.send(reply)
                    print(f"Replied to request from {msg.sender}")
                else:
                    # generic acknowledgement
                    print(f"No handler for message body; ignoring or log for manual handling.")
            else:
                # timed out waiting for messages; just continue waiting
                await asyncio.sleep(0.1)

    class HeartbeatBehav(PeriodicBehaviour):
        async def on_start(self):
            self.counter = 0

        async def run(self):
            peers = self.agent.get("peers") or []
            if not peers:
                return
            # Use firewall to send heartbeats if available
            fw = self.agent.get("firewall")
            for p in peers:
                body = f"HEARTBEAT from {str(self.agent.jid)} count={self.counter}"
                if fw:
                    sent = await fw.send_through_firewall(p, body)
                    if not sent:
                        print(f"Heartbeat blocked by firewall for {p}")
                else:
                    msg = Message(to=p)
                    msg.body = f"HEARTBEAT from {str(self.agent.jid)} count={self.counter}"
                    await self.send(msg)
            print(f"Sent heartbeat to {len(peers)} peers (count={self.counter})")
            self.counter += 1

    async def setup(self):
        print(f"NodeAgent {str(self.jid)} starting...")
        # Add firewall behaviour and store reference for other behaviours
        fw = FirewallBehaviour()
        self.add_behaviour(fw)
        self.set("firewall", fw)

        # Mark local nodes for this agent so the firewall can treat intra-subnet
        # traffic as internal (bypass router-level external checks when desired).
        # This uses the peers list (set by the launcher) as the local_nodes set.
        peers = self.get("peers") or []
        local_nodes = set(peers)
        # include self
        try:
            local_nodes.add(str(self.jid))
        except Exception:
            pass
        self.set("local_nodes", local_nodes)
        # mark role so firewall can differentiate behaviour
        self.set("role", "node")

        recv = self.RecvBehav()
        self.add_behaviour(recv)


## Interactive mode removed per user request; node runs non-interactively


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Agent JID (e.g. node1@localhost)")
    parser.add_argument("--password", required=True, help="Agent password")
    parser.add_argument("--peers", default="", help="Comma-separated peer JIDs (optional)")
    parser.add_argument("--heartbeat", type=int, default=0, help="Heartbeat interval in seconds (0 to disable)")
    parser.add_argument("--no-auto-register", dest="auto_register", action="store_false", help="Disable auto_register when starting the agent")
    args = parser.parse_args()

    print("Node (workstation/server) starting in non-interactive mode.")
    jid = args.jid
    passwd = args.password
    peers = [p.strip() for p in args.peers.split(",") if p.strip()]

    agent = NodeAgent(jid, passwd)
    agent.set("peers", peers)

    try:
        await agent.start(auto_register=args.auto_register)
    except Exception as e:
        print(f"Failed to start agent {jid}: {e}")
        print("If auto-register failed, create the account on the XMPP server or enable in-band registration.")
        return

    # start heartbeat if requested
    if args.heartbeat and args.heartbeat > 0 and peers:
        hb = agent.HeartbeatBehav(period=args.heartbeat)
        agent.add_behaviour(hb)

    print("Node running (non-interactive). Press Ctrl+C to stop.")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        print("Keyboard interrupt received, stopping agent...")
    finally:
        await agent.stop()
        print("Agent stopped. Goodbye.")


if __name__ == "__main__":
    spade.run(main())
