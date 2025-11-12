"""Router agent for the simulated network.

RouterAgent is implemented as a standalone SPADE Agent (not subclassing NodeAgent).
It attaches a FirewallBehaviour, accepts messages from local nodes or other routers,
sends a copy of each message to configured monitoring agent(s) before forwarding,
and forwards messages according to a simple static routing table.

Message contract (convention): sending agents should send to the router JID and
include the intended destination under metadata key 'dst' (exact destination JID).

Usage example:
  python new/router.py --jid router@localhost --password secret --local node1@localhost,node2@localhost --routes "node3@localhost:routerB@localhost" --monitors monitor@localhost

Notes:
 - This implementation sends a copy to monitors first, then waits briefly and forwards.
 - Firewall control messages (protocol 'firewall-control') are supported by FirewallBehaviour.
"""

import argparse
import asyncio
import datetime
import getpass
from typing import Dict, Set, List, Any
import json
from spade.behaviour import CyclicBehaviour
from spade.behaviour import OneShotBehaviour
from spade.template import Template
import time

import spade
from spade.agent import Agent
from spade.message import Message

from firewall import RouterFirewallBehaviour


def _log(agent_type: str, jid: str, msg: str) -> None:
	ts = datetime.datetime.now().strftime("%H:%M:%S")
	print(f"[{ts}] [{agent_type} {jid}] {msg}")


class RouterAgent(Agent):
	"""A simple router agent that forwards messages between nodes/routers.

	Attributes stored on the agent:
	  - routing_table: Dict[str, str] mapping destination JID or prefix -> next_hop_jid
	  - local_nodes: Set[str] of JIDs directly reachable
	  - monitor_jids: list of monitoring agent JIDs to receive copies
	"""

	class RouterBehav(CyclicBehaviour):
		async def run(self):
			msg = await self.receive(timeout=1)
			if not msg:
				return

			_log("Router", str(self.agent.jid), f"received msg from {msg.sender}")

			# Firewall inbound check
			fw = self.agent.get("firewall")
			if fw:
				allowed = await fw.allow_message(msg)
				if not allowed:
					_log("Router", str(self.agent.jid), f"Firewall blocked inbound message from {msg.sender}")
					return
				else:
					_log("Router", str(self.agent.jid), f"Firewall allowed message from {msg.sender}")


			# Try to parse body JSON for special control messages (e.g., cnp-request)
			dst = None
			parsed = None
			try:
				parsed = json.loads(str(msg.body)) if msg.body else None
			except Exception:
				parsed = None

			# If this is a CNP request from a node asking the router to run the auction,
			# (CNP functionality removed) normal forwarding continues

			# Determine destination for normal forwarding
			if msg.metadata and "dst" in msg.metadata:
				dst = msg.metadata.get("dst")
			else:
				# fallback: use msg.to if provided (may be router itself)
				dst = str(msg.to) if msg.to else None

			if not dst:
				_log("Router", str(self.agent.jid), "message missing dst metadata; dropping")
				return

			# Check TTL (Time-To-Live) to prevent routing loops
			ttl = int(msg.metadata.get("ttl", 64)) if msg.metadata else 64
			if ttl <= 0:
				_log("Router", str(self.agent.jid), f"TTL expired for packet to {dst}; dropping")
				return
			ttl -= 1  # Decrement TTL for next hop

			# Send copy to monitoring agents first (so monitor sees traffic before forwarding)
			monitors = self.agent.get("monitor_jids") or []
			internal_monitors = self.agent.get("internal_monitor_jids") or []
			# determine whether message is internal (both src and dst in local_nodes)
			local = self.agent.get("local_nodes") or set()
			sender_jid = str(msg.sender) if msg.sender else None
			is_internal = False
			if sender_jid and dst and local:
				is_internal = (sender_jid in local and dst in local)

			# choose which monitors to notify: internal monitors for intra-subnet traffic,
			# otherwise global/external monitors
			target_monitors = internal_monitors if is_internal and internal_monitors else monitors
			for m in target_monitors:
				# Use firewall helper to send copies so rules apply
				copy_body = f"COPY {str(msg.sender)} -> {dst} : {msg.body}"
				if fw:
					await fw.send_through_firewall(m, copy_body, metadata={"protocol": "network-copy"})
				else:
					cm = Message(to=m)
					cm.set_metadata("protocol", "network-copy")
					cm.body = copy_body
					await self.send(cm)

			# Small pause to allow monitors to react (monitoring agents are simple and may update firewall rules)
			await asyncio.sleep(0.15)

			# Forwarding decision: local nodes first, then routing table
			local = self.agent.get("local_nodes") or set()
			routing: Dict[str, str] = self.agent.get("routing_table") or {}

			if dst in local:
				# direct delivery
				out = Message(to=dst)
				out.body = msg.body
				out.set_metadata("via", str(self.agent.jid))
				out.set_metadata("ttl", str(ttl))  # Pass TTL along
				if fw:
					sent = await fw.send_through_firewall(dst, out.body, metadata={"via": str(self.agent.jid), "ttl": str(ttl)})
					if sent:
						_log("Router", str(self.agent.jid), f"Forwarded locally to {dst}")
					else:
						_log("Router", str(self.agent.jid), f"Firewall blocked forwarding to local {dst}")
				else:
					await self.send(out)
					print(f"Forwarded locally to {dst}")
				return

			# Exact match route
			next_hop = routing.get(dst)
			# simple prefix/pattern matching: allow keys ending with '*' to indicate prefix
			if not next_hop:
				for pat, nh in routing.items():
					if pat.endswith("*") and dst.startswith(pat[:-1]):
						next_hop = nh
						break

			if not next_hop:
				_log("Router", str(self.agent.jid), f"No route for {dst}; dropping packet")
				return

			# Forward to next hop
			fwd_body = msg.body
			# Use firewall helper if present
			if fw:
				sent_ok = await fw.send_through_firewall(next_hop, fwd_body, metadata={"dst": dst, "via": str(self.agent.jid), "ttl": str(ttl)})
			else:
				fwd = Message(to=next_hop)
				fwd.body = fwd_body
				fwd.set_metadata("dst", dst)
				fwd.set_metadata("via", str(self.agent.jid))
				fwd.set_metadata("ttl", str(ttl))
				await self.send(fwd)
				sent_ok = True

			if sent_ok:
				_log("Router", str(self.agent.jid), f"Forwarded {dst} via next hop {next_hop}")
			else:
				_log("Router", str(self.agent.jid), f"Firewall prevented forwarding to {next_hop} for dst {dst}")

	async def setup(self):
		_log("Router", str(self.jid), "starting...")

		# attach a router-specific firewall behaviour and store reference
		fw = RouterFirewallBehaviour()
		self.add_behaviour(fw)
		self.set("firewall", fw)

		# mark role so firewall can behave differently (router bypasses intra-subnet checks)
		self.set("role", "router")

		# initialize routing structures but only set defaults if not already configured
		if not self.get("routing_table"):
			self.set("routing_table", {})
		if not self.get("local_nodes"):
			self.set("local_nodes", set())
		if not self.get("monitor_jids"):
			self.set("monitor_jids", [])
		if not self.get("internal_monitor_jids"):
			self.set("internal_monitor_jids", [])

		# Print current configuration for visibility when the router starts
		rt = self.get("routing_table") or {}
		ln = self.get("local_nodes") or set()
		monitors = self.get("monitor_jids") or []
		internal = self.get("internal_monitor_jids") or []
		_log("Router", str(self.jid), "configuration:")
		print(f"  local_nodes: {sorted(list(ln))}")
		print(f"  routing_table: {rt}")
		print(f"  monitors: {monitors}, internal_monitors: {internal}")

		# add main router behaviour
		self.add_behaviour(self.RouterBehav())

	# (CNP manager removed) router no longer implements start_cnp

	# convenience helpers for runtime configuration
	def add_route(self, dst_pattern: str, next_hop: str):
		rt = self.get("routing_table") or {}
		rt[dst_pattern] = next_hop
		self.set("routing_table", rt)

	def add_local_node(self, jid: str):
		ln = self.get("local_nodes") or set()
		ln.add(jid)
		self.set("local_nodes", ln)
		# log when a node connects to this router
		_log("Router", str(self.jid), f"node {jid} connected; local_nodes now: {sorted(list(ln))}")

	def add_internal_monitor(self, jid: str):
		ims = self.get("internal_monitor_jids") or []
		ims.append(jid)
		self.set("internal_monitor_jids", ims)


async def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--jid", required=True, help="Router agent JID")
	parser.add_argument("--password", required=False, help="Agent password; if omitted you'll be prompted")
	parser.add_argument("--local", default="", help="Comma-separated local node JIDs attached to this router")
	parser.add_argument("--routes", default="", help="Comma-separated routes in the form dst:next_hop (dst may use * as suffix for prefix match)")
	parser.add_argument("--monitors", default="", help="Comma-separated monitoring agent JIDs to receive copies")
	parser.add_argument("--internal-monitors", default="", help="Comma-separated monitoring agent JIDs for intra-subnet monitoring")
	parser.add_argument("--no-auto-register", dest="auto_register", action="store_false", help="Disable auto_register when starting the agent")
	args = parser.parse_args()

	passwd = args.password or getpass.getpass()
	local_nodes = [p.strip() for p in args.local.split(',') if p.strip()]
	monitors = [p.strip() for p in args.monitors.split(',') if p.strip()]
	internal_monitors = [p.strip() for p in args.internal_monitors.split(',') if p.strip()]

	agent = RouterAgent(args.jid, passwd)
	agent.set("monitor_jids", monitors)
	agent.set("internal_monitor_jids", internal_monitors)

	# parse routes
	for r in [x.strip() for x in args.routes.split(',') if x.strip()]:
		if ':' in r:
			dst, nh = r.split(':', 1)
			agent.add_route(dst.strip(), nh.strip())

	for n in local_nodes:
		agent.add_local_node(n)

	try:
		await agent.start(auto_register=args.auto_register)
	except Exception as e:
		_log("Router", args.jid, f"Failed to start: {e}")
		return

	_log("Router", args.jid, "running. Press Ctrl+C to stop")
	try:
		await spade.wait_until_finished(agent)
	except KeyboardInterrupt:
		_log("Router", args.jid, "Stopping...")
	finally:
		await agent.stop()


if __name__ == "__main__":
	spade.run(main())