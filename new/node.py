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
import json
import random


def _now_ts():
    return asyncio.get_event_loop().time()
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

                # try to parse structured JSON messages (e.g., CNP, resource reports)
                parsed = None
                body_text = (msg.body or "").strip()
                try:
                    parsed = json.loads(body_text)
                except Exception:
                    parsed = None

                # handle cnp-request-response messages (router replies to node-initiated requests)
                if parsed and isinstance(parsed, dict) and parsed.get("protocol") == "cnp-request-response":
                    task_id = parsed.get("task_id")
                    result = parsed.get("result", False)
                    store = self.agent.get("cnp_request_results") or {}
                    store[task_id] = result
                    self.agent.set("cnp_request_results", store)
                    print(f"Stored cnp-request-response for {task_id}: {result}")
                    return

                # handle structured CNP messages first
                if parsed and isinstance(parsed, dict) and parsed.get("protocol") == "cnp":
                    ctype = parsed.get("type")
                    task_id = parsed.get("task_id")
                    # Participant handling: CFP -> send PROPOSE
                    if ctype == "CFP":
                        # compute simple proposal based on available cpu and bandwidth
                        cpu = float(self.agent.get("cpu_usage") or 0.0)
                        bw = float(self.agent.get("bandwidth_usage") or 0.0)
                        # higher available (inverse of usage) is better
                        avail_cpu = max(0.0, 100.0 - cpu)
                        avail_bw = max(0.0, 100.0 - bw)
                        proposal = {"avail_cpu": avail_cpu, "avail_bw": avail_bw}
                        prop_msg = Message(to=str(msg.sender))
                        prop_msg.body = json.dumps({"protocol": "cnp", "type": "PROPOSE", "task_id": task_id, "proposal": proposal})
                        await self.send(prop_msg)
                        print(f"Sent PROPOSE for task {task_id} to {msg.sender}: {proposal}")
                        # Do NOT record the proposal on the participant — proposals
                        # must be delivered back to the manager who will collect them.
                        return

                    # Participant accepted: perform task and reply INFORM when done
                    if ctype == "ACCEPT_PROPOSAL":
                        task = parsed.get("task") or {}
                        duration = float(task.get("duration", 1.0))
                        load = float(task.get("cpu_load", 10.0))
                        # schedule a simulated task: increase cpu usage for duration
                        active = self.agent.get("active_tasks") or {}
                        end_ts = _now_ts() + duration
                        active[task_id] = {"end": end_ts, "load": load}
                        self.agent.set("active_tasks", active)
                        print(f"Accepted task {task_id}; executing for {duration}s (cpu load +{load})")

                        # simulate work asynchronously and send INFORM when done
                        async def _do_and_inform():
                            await asyncio.sleep(duration)
                            inf = Message(to=str(msg.sender))
                            inf.body = json.dumps({"protocol": "cnp", "type": "INFORM", "task_id": task_id, "result": "done"})
                            await self.send(inf)
                            # cleanup active tasks
                            active = self.agent.get("active_tasks") or {}
                            if task_id in active:
                                del active[task_id]
                                self.agent.set("active_tasks", active)
                            print(f"Completed task {task_id}; sent INFORM to {msg.sender}")

                        self.agent.loop.create_task(_do_and_inform())
                        return

                    # Manager/recipient handling: PROPOSE/REJECT/INFORM should be
                    # stored so a running manager (start_cnp) can collect them.
                    if ctype == "PROPOSE":
                        proposal = parsed.get("proposal")
                        store = self.agent.get("cnp_proposals") or {}
                        # store proposals keyed by task_id; record sender and proposal
                        store.setdefault(task_id, []).append({"from": str(msg.sender), "proposal": proposal})
                        self.agent.set("cnp_proposals", store)
                        print(f"Stored PROPOSE for task {task_id} from {msg.sender}: {proposal}")
                        return

                    if ctype in ("REJECT_PROPOSAL", "INFORM"):
                        print(f"CNP message ({ctype}) for task {task_id} received: {parsed}")
                        cnp_store = self.agent.get("cnp_proposals") or {}
                        cnp_store.setdefault(task_id or "_misc", []).append({"msg": parsed, "from": str(msg.sender)})
                        self.agent.set("cnp_proposals", cnp_store)
                        return

                # simple protocol handling for legacy/plain messages
                body = body_text
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

    class ResourceBehav(PeriodicBehaviour):
        async def on_start(self):
            # initialize active tasks store
            self.agent.set("active_tasks", {})

        async def run(self):
            # simulate CPU and bandwidth usage: base noise plus active tasks
            base_cpu = random.uniform(5.0, 15.0)
            base_bw = random.uniform(2.0, 10.0)
            active = self.agent.get("active_tasks") or {}
            extra_cpu = 0.0
            # remove finished tasks
            now = _now_ts()
            to_delete = []
            for tid, info in list(active.items()):
                if info.get("end", 0) <= now:
                    to_delete.append(tid)
                else:
                    extra_cpu += float(info.get("load", 0.0))
            for tid in to_delete:
                del active[tid]
            self.agent.set("active_tasks", active)

            cpu_usage = min(100.0, base_cpu + extra_cpu)
            bw_usage = min(100.0, base_bw + extra_cpu * 0.2)
            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bw_usage)
            print(f"Resource update for {self.agent.jid}: cpu={cpu_usage:.1f}% bw={bw_usage:.1f}% (active_tasks={len(active)})")

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

        # initialize resource usage tracking and CNP store
        self.set("cpu_usage", 5.0)
        self.set("bandwidth_usage", 5.0)
        self.set("cnp_proposals", {})
        # store for node-initiated CNP request results (router responses)
        self.set("cnp_request_results", {})

        # resource simulation behaviour (periodic)
        res = self.ResourceBehav(period=2)
        self.add_behaviour(res)

        recv = self.RecvBehav()
        self.add_behaviour(recv)

    # Node agents are participants only; CNP manager is hosted by the router.


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
