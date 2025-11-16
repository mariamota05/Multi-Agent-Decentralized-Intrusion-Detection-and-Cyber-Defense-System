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


def _log(agent_type: str, jid: str, msg: str) -> None:
    """Uniform log helper used across this file.

    Format: [HH:MM:SS] [<AgentType> <jid>] <msg>
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


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
                        _log("NodeAgent", str(self.agent.jid), f"Firewall blocked inbound message from {msg.sender}")
                        return
                _log("NodeAgent", str(self.agent.jid), f"Received from {msg.sender}: {msg.body}")
                
                # Emit packet event for visualization (router -> node)
                viz = self.agent.get("_visualizer")
                if viz and msg.metadata and msg.metadata.get("via"):
                    via = msg.metadata.get("via")
                    viz.add_packet(via, str(self.agent.jid))
                
                # EVERY message processing consumes base resources
                # Add a small processing task for receiving and parsing the message
                active = self.agent.get("active_tasks") or {}
                counter = self.agent.get("task_counter") or 0
                counter += 1
                tid = f"recv-{counter}"
                self.agent.set("task_counter", counter)
                # Base message processing: 2% CPU for 0.5 seconds
                active[tid] = {"end": _now_ts() + 0.5, "load": 2.0}
                self.agent.set("active_tasks", active)
                
                # notify resource monitor that something happened (message arrived)
                try:
                    self.agent._force_pprint = True
                    if hasattr(self.agent, "_resource_event"):
                        self.agent._resource_event.set()
                except Exception:
                    pass

                # try to parse structured JSON messages (e.g., CNP, resource reports)
                parsed = None
                body_text = (msg.body or "").strip()
                try:
                    parsed = json.loads(body_text)
                except Exception:
                    parsed = None

                # CNP support is currently disabled; treat JSON messages as opaque

                # If the message carries task information (metadata 'task' JSON,
                # parsed JSON with a 'task' field, or legacy 'TASK:' body),
                # schedule it as an active task so ResourceBehav will account
                # for its load until completion.
                task_info = None
                try:
                    if msg.metadata and "task" in msg.metadata:
                        raw = msg.metadata.get("task")
                        if isinstance(raw, str):
                            try:
                                task_info = json.loads(raw)
                            except Exception:
                                task_info = None
                        else:
                            task_info = raw
                except Exception:
                    task_info = None

                if not task_info and isinstance(parsed, dict) and "task" in parsed:
                    task_info = parsed.get("task")

                if not task_info and body_text.upper().startswith("TASK:"):
                    rest = body_text.split("TASK:", 1)[1].strip()
                    try:
                        task_info = json.loads(rest)
                    except Exception:
                        # fallback to simple key=value;semicolons
                        try:
                            parts = [p.strip() for p in rest.split(";") if p.strip()]
                            ti = {}
                            for p in parts:
                                if "=" in p:
                                    k, v = p.split("=", 1)
                                    try:
                                        ti[k.strip()] = float(v.strip())
                                    except Exception:
                                        ti[k.strip()] = v.strip()
                            task_info = ti or None
                        except Exception:
                            task_info = None

                if task_info:
                    active = self.agent.get("active_tasks") or {}
                    counter = self.agent.get("task_counter") or 0
                    counter += 1
                    tid = f"t{counter}-{int(_now_ts())}"
                    self.agent.set("task_counter", counter)
                    duration = float(task_info.get("duration", task_info.get("dur", 1.0)))
                    load = float(task_info.get("cpu_load", task_info.get("load", task_info.get("cpu", 0.0))))
                    active[tid] = {"end": _now_ts() + duration, "load": load}
                    self.agent.set("active_tasks", active)
                    _log("NodeAgent", str(self.agent.jid), f"Scheduled task {tid}: duration={duration} load={load}")
                    # signal resource monitor to pprint this change
                    try:
                        self.agent._force_pprint = True
                        if hasattr(self.agent, "_resource_event"):
                            self.agent._resource_event.set()
                    except Exception:
                        pass

                # simple protocol handling for legacy/plain messages
                body = body_text
                if body.upper() == "PING":
                    # Sending a reply also consumes resources
                    active = self.agent.get("active_tasks") or {}
                    counter = self.agent.get("task_counter") or 0
                    counter += 1
                    tid = f"send-{counter}"
                    self.agent.set("task_counter", counter)
                    # Sending: 1.5% CPU for 0.3 seconds
                    active[tid] = {"end": _now_ts() + 0.3, "load": 1.5}
                    self.agent.set("active_tasks", active)
                    
                    reply = Message(to=str(msg.sender))
                    reply.body = "PONG"
                    await self.send(reply)
                    _log("NodeAgent", str(self.agent.jid), f"Sent PONG to {msg.sender}")
                elif body.startswith(("BLOCK_JID:", "RATE_LIMIT:", "TEMP_BLOCK:", "SUSPEND_ACCESS:", 
                                     "QUARANTINE_ADVISORY:", "ADMIN_ALERT:")):
                    # Handle any firewall control command from incident response
                    fw = self.agent.get("firewall")
                    if fw:
                        # Forward to firewall by creating a control message
                        control_msg = Message(to=str(self.agent.jid))
                        control_msg.set_metadata("protocol", "firewall-control")
                        control_msg.body = body
                        control_msg.sender = msg.sender  # Preserve original sender
                        await fw._handle_control(control_msg)
                        
                        # Log specific command type
                        cmd_type = body.split(":", 1)[0]
                        _log("NodeAgent", str(self.agent.jid), f"Processed firewall command: {cmd_type}")
                    else:
                        _log("NodeAgent", str(self.agent.jid), "No firewall available to process command")
                elif body.startswith("REQUEST:"):
                    content = body.split("REQUEST:", 1)[1]
                    # Processing a request consumes more CPU
                    active = self.agent.get("active_tasks") or {}
                    counter = self.agent.get("task_counter") or 0
                    counter += 1
                    tid = f"proc-{counter}"
                    self.agent.set("task_counter", counter)
                    # Request processing: 5% CPU for 1 second (more intensive)
                    active[tid] = {"end": _now_ts() + 1.0, "load": 5.0}
                    self.agent.set("active_tasks", active)
                    
                    reply = Message(to=str(msg.sender))
                    reply.body = f"RESPONSE: processed '{content.strip()}'"
                    await self.send(reply)
                    _log("NodeAgent", str(self.agent.jid), f"Replied to request from {msg.sender}")
                else:
                    # generic acknowledgement
                    _log("NodeAgent", str(self.agent.jid), "No handler for message body; ignoring or log for manual handling.")
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
                        _log("NodeAgent", str(self.agent.jid), f"Heartbeat blocked by firewall for {p}")
                else:
                    msg = Message(to=p)
                    msg.body = f"HEARTBEAT from {str(self.agent.jid)} count={self.counter}"
                    await self.send(msg)
            _log("NodeAgent", str(self.agent.jid), f"Sent heartbeat to {len(peers)} peers (count={self.counter})")
            self.counter += 1

    class ResourceBehav(CyclicBehaviour):
        async def on_start(self):
            # initialize active tasks store and last-known state
            self.agent.set("active_tasks", {})
            self._last_active_count = 0
            # print initial resource snapshot so initialization is visible
            # allow a short-lived adjustment (set by other behaviours on send/receive)
            adjust = float(getattr(self.agent, "_send_adjust", 0.0) or 0.0)
            # Use deterministic base values if agent configured them (resource_seed or fixed_base_cpu/bw)
            try:
                base_cpu = float(self.agent.get("base_cpu", 10.0)) + adjust
            except Exception:
                base_cpu = 10.0 + adjust
            try:
                base_bw = float(self.agent.get("base_bw", 5.0))
            except Exception:
                base_bw = 5.0
            cpu_usage = min(100.0, base_cpu)
            bw_usage = min(100.0, base_bw)
            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bw_usage)
            _log("NodeAgent", str(self.agent.jid), f"Resource init: cpu={cpu_usage:.1f}% bw={bw_usage:.1f}% active_tasks=0")

        async def run(self):
            # Event-driven resource monitor: wakes on agent._resource_event or
            # after a timeout equal to the next task end. Prints state via pprint
            # whenever tasks are added/removed or when a message arrives.
            active = self.agent.get("active_tasks") or {}
            now = _now_ts()

            # Remove finished tasks
            removed = []
            for tid, info in list(active.items()):
                if info.get("end", 0) <= now:
                    removed.append(tid)
                else:
                    pass
            if removed:
                for tid in removed:
                    del active[tid]
                self.agent.set("active_tasks", active)

            # Compute resource usage
            extra_cpu = 0.0
            for info in active.values():
                extra_cpu += float(info.get("load", 0.0))

            # Use configured deterministic base values when available
            try:
                base_cpu = float(self.agent.get("base_cpu", 10.0))
            except Exception:
                base_cpu = 10.0
            try:
                base_bw = float(self.agent.get("base_bw", 5.0))
            except Exception:
                base_bw = 5.0

            # include any one-shot send adjustment when reporting
            send_adj = float(getattr(self.agent, "_send_adjust", 0.0) or 0.0)

            cpu_usage = min(100.0, base_cpu + extra_cpu + send_adj)
            bw_usage = min(100.0, base_bw + extra_cpu * 0.2)
            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bw_usage)

            # Print state when something changed (task added/removed) or first run
            force = bool(getattr(self.agent, "_force_pprint", False))
            if removed or len(active) != self._last_active_count or force:
                # concise single-line summary for simplicity
                _log("NodeAgent", str(self.agent.jid), f"Resource update: cpu={cpu_usage:.1f}% bw={bw_usage:.1f}% active_tasks={len(active)}")
                if active:
                    # small, compact list of active task ids
                    _log("NodeAgent", str(self.agent.jid), f"Active tasks: {', '.join(list(active.keys()))}")
                # Update visualizer with resource stats
                viz = self.agent.get("_visualizer")
                if viz:
                    viz.update_agent_stats(str(self.agent.jid), cpu=cpu_usage, bandwidth=bw_usage)
                try:
                    # clear the force flag after printing
                    if force:
                        self.agent._force_pprint = False
                except Exception:
                    pass
            else:
                # occasional lightweight log to show steady state (optional)
                pass

            self._last_active_count = len(active)

            # Determine sleep/wake behavior: wait until next task end or an explicit event
            next_end = None
            for info in active.values():
                e = info.get("end", 0)
                if not next_end or e < next_end:
                    next_end = e

            timeout = None
            if next_end:
                timeout = max(0.1, next_end - _now_ts())

            ev = getattr(self.agent, "_resource_event", None)
            try:
                event_woken = False
                if ev:
                    if timeout is None:
                        # wait indefinitely until an event
                        await ev.wait()
                        event_woken = True
                    else:
                        try:
                            await asyncio.wait_for(ev.wait(), timeout=timeout)
                            event_woken = True
                        except asyncio.TimeoutError:
                            # timeout means re-evaluate finished tasks
                            event_woken = False

                    # if the event was set, clear it now
                    if event_woken:
                        try:
                            ev.clear()
                        except Exception:
                            pass
                else:
                    # fallback to a short sleep
                    await asyncio.sleep(0.5)

                # If we woke because of an explicit event (send/receive/task schedule),
                # print the concise summary even if active count didn't change.
                if event_woken:
                    _log("NodeAgent", str(self.agent.jid), f"Resource update: cpu={cpu_usage:.1f}% bw={bw_usage:.1f}% active_tasks={len(active)}")
                    if active:
                        _log("NodeAgent", str(self.agent.jid), f"Active tasks: {', '.join(list(active.keys()))}")
                    # Update visualizer with resource stats
                    viz = self.agent.get("_visualizer")
                    if viz:
                        viz.update_agent_stats(str(self.agent.jid), cpu=cpu_usage, bandwidth=bw_usage)
                    # clear any force flag and one-shot send adjustment
                    try:
                        self.agent._force_pprint = False
                    except Exception:
                        pass
                    try:
                        if getattr(self.agent, "_send_adjust", 0.0):
                            self.agent._send_adjust = 0.0
                    except Exception:
                        pass
            except Exception:
                # ensure the behaviour does not crash
                await asyncio.sleep(0.5)

    async def setup(self):
        print(f"[NodeAgent {str(self.jid)}] starting...")
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

        # initialize resource usage tracking
        self.set("cpu_usage", 5.0)
        self.set("bandwidth_usage", 5.0)

        # initialize an event for event-driven resource monitoring
        try:
            self._resource_event = asyncio.Event()
        except Exception:
            self._resource_event = None
        # helper flag to force pprint on next resource cycle
        self._force_pprint = False
        # simple task counter
        self.set("task_counter", 0)

        # deterministic resource baseline option: set base_cpu/base_bw once if configured
        # No randomness - use fixed base values
        if not self.get("base_cpu"):
            if self.get("fixed_base_cpu") is not None:
                self.set("base_cpu", float(self.get("fixed_base_cpu")))
            else:
                self.set("base_cpu", 10.0)
        if not self.get("base_bw"):
            if self.get("fixed_base_bw") is not None:
                self.set("base_bw", float(self.get("fixed_base_bw")))
            else:
                self.set("base_bw", 5.0)

        # resource simulation behaviour (event-driven)
        res = self.ResourceBehav()
        self.add_behaviour(res)

        recv = self.RecvBehav()
        self.add_behaviour(recv)

        # CNP support removed: nodes operate with simple messaging and resources only

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

    _log("NodeAgent", args.jid, "Node (workstation/server) starting in non-interactive mode.")
    jid = args.jid
    passwd = args.password
    peers = [p.strip() for p in args.peers.split(",") if p.strip()]

    agent = NodeAgent(jid, passwd)
    agent.set("peers", peers)

    try:
        await agent.start(auto_register=args.auto_register)
    except Exception as e:
        _log("NodeAgent", jid, f"Failed to start: {e}")
        _log("NodeAgent", jid, "If auto-register failed, create the account on the XMPP server or enable in-band registration.")
        return

    # start heartbeat if requested
    if args.heartbeat and args.heartbeat > 0 and peers:
        hb = agent.HeartbeatBehav(period=args.heartbeat)
        agent.add_behaviour(hb)

    _log("NodeAgent", jid, "running (non-interactive). Press Ctrl+C to stop")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        _log("NodeAgent", jid, "Keyboard interrupt received, stopping agent...")
    finally:
        await agent.stop()
        _log("NodeAgent", jid, "Agent stopped. Goodbye.")


if __name__ == "__main__":
    spade.run(main())
