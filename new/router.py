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

			now = datetime.datetime.now().time()
			print(f"[{now}] Router {self.agent.jid} received msg from {msg.sender}")

			# Firewall inbound check
			fw = self.agent.get("firewall")
			if fw:
				allowed = await fw.allow_message(msg)
				if not allowed:
					print(f"Firewall blocked inbound message from {msg.sender}")
					return


			# Try to parse body JSON for special control messages (e.g., cnp-request)
			dst = None
			parsed = None
			try:
				parsed = json.loads(str(msg.body)) if msg.body else None
			except Exception:
				parsed = None

			# If this is a CNP request from a node asking the router to run the auction,
			# trigger the router-managed CNP and ACK the requester.
			if parsed and isinstance(parsed, dict) and parsed.get("protocol") == "cnp-request":
				requester = str(msg.sender)
				task_id = parsed.get("task_id")
				task = parsed.get("task") or {}
				targets = parsed.get("targets") or list(self.agent.get("local_nodes") or [])

				# Acknowledge receipt to requester
				fw = self.agent.get("firewall")
				ack = {"protocol": "cnp-request-response", "type": "ACK", "task_id": task_id}
				if fw:
					await fw.send_through_firewall(requester, json.dumps(ack), metadata={"protocol": "cnp-request-response"})
				else:
					mack = Message(to=requester)
					mack.set_metadata("protocol", "cnp-request-response")
					mack.body = json.dumps(ack)
					await self.send(mack)

				# start CNP manager in background and send result back to requester when done
				async def _run_and_report():
					res = await self.agent.start_cnp(task_id, task, targets)
					report = {"protocol": "cnp-request-response", "type": "RESULT", "task_id": task_id, "result": res}
					if fw:
						await fw.send_through_firewall(requester, json.dumps(report), metadata={"protocol": "cnp-request-response"})
					else:
						mres = Message(to=requester)
						mres.set_metadata("protocol", "cnp-request-response")
						mres.body = json.dumps(report)
						await self.send(mres)

				# schedule background task and continue
				asyncio.create_task(_run_and_report())
				return

			# Determine destination for normal forwarding
			if msg.metadata and "dst" in msg.metadata:
				dst = msg.metadata.get("dst")
			else:
				# fallback: use msg.to if provided (may be router itself)
				dst = str(msg.to) if msg.to else None

			if not dst:
				print("Router: message missing dst metadata; dropping")
				return

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
				if fw:
					sent = await fw.send_through_firewall(dst, out.body, metadata={"via": str(self.agent.jid)})
					if sent:
						print(f"Forwarded locally to {dst}")
					else:
						print(f"Firewall blocked forwarding to local {dst}")
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
				print(f"No route for {dst}; dropping packet")
				return

			# Forward to next hop
			fwd_body = msg.body
			# Use firewall helper if present
			if fw:
				sent_ok = await fw.send_through_firewall(next_hop, fwd_body, metadata={"dst": dst, "via": str(self.agent.jid)})
			else:
				fwd = Message(to=next_hop)
				fwd.body = fwd_body
				fwd.set_metadata("dst", dst)
				fwd.set_metadata("via", str(self.agent.jid))
				await self.send(fwd)
				sent_ok = True

			if sent_ok:
				print(f"Forwarded {dst} via next hop {next_hop}")
			else:
				print(f"Firewall prevented forwarding to {next_hop} for dst {dst}")

	async def setup(self):
		print(f"RouterAgent {str(self.jid)} starting...")

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
		print(f"Router {str(self.jid)} configuration:")
		print(f"  local_nodes: {sorted(list(ln))}")
		print(f"  routing_table: {rt}")
		print(f"  monitors: {monitors}, internal_monitors: {internal}")

		# add main router behaviour
		self.add_behaviour(self.RouterBehav())

	# CNP manager behaviour: runs a single CNP round (CFP -> collect PROPOSE -> accept/reject -> wait INFORM)
	class CNPManagerBehav(OneShotBehaviour):
		def __init__(self, task_id: str, task: dict, targets: List[str], proposal_timeout: float, inform_timeout: float, result_future: Any, *args, **kwargs):
			super().__init__(*args, **kwargs)
			self.task_id = task_id
			self.task = task
			self.targets = targets
			self.proposal_timeout = proposal_timeout
			self.inform_timeout = inform_timeout
			self.result_future = result_future

		async def run(self):
			fw = self.agent.get("firewall")
			# build CFP body
			cfp = {"protocol": "cnp", "type": "CFP", "task_id": self.task_id, "task": self.task}
			# send CFP to targets via firewall helper when available
			for t in self.targets:
				body = json.dumps(cfp)
				if fw:
					try:
						await fw.send_through_firewall(t, body, metadata={"protocol": "cnp"})
					except Exception:
						pass
				else:
					m = Message(to=t)
					m.set_metadata("protocol", "cnp")
					m.body = body
					await self.send(m)

			print(f"Sent CFP {self.task_id} to {len(self.targets)} targets; waiting {self.proposal_timeout}s for proposals")

			# collect proposals until timeout
			proposals = []
			end = time.time() + self.proposal_timeout
			while time.time() < end:
				remaining = end - time.time()
				msg = await self.receive(timeout=min(0.5, remaining))
				if not msg:
					continue
				# try parse body JSON
				try:
					parsed = json.loads(str(msg.body))
				except Exception:
					parsed = None
				if parsed and isinstance(parsed, dict) and parsed.get("protocol") == "cnp" and parsed.get("type") == "PROPOSE" and parsed.get("task_id") == self.task_id:
					proposal = parsed.get("proposal")
					proposals.append({"from": str(msg.sender), "proposal": proposal})
					print(f"Manager stored proposal from {msg.sender}: {proposal}")

			print(f"Collected {len(proposals)} proposals for {self.task_id}")

			if not proposals:
				print(f"No proposals received for {self.task_id}; aborting CNP")
				self.result_future.set_result(None)
				return

			# choose best: highest avail_cpu
			best = None
			best_score = -1
			for p in proposals:
				pr = p.get("proposal") or {}
				avail = float(pr.get("avail_cpu", 0.0))
				if avail > best_score:
					best_score = avail
					best = p

			winner = best.get("from")
			# send ACCEPT to winner, REJECT to others
			for p in proposals:
				dest = p.get("from")
				if dest == winner:
					body = json.dumps({"protocol": "cnp", "type": "ACCEPT_PROPOSAL", "task_id": self.task_id, "task": self.task})
					if fw:
						await fw.send_through_firewall(dest, body, metadata={"protocol": "cnp"})
					else:
						m = Message(to=dest)
						m.set_metadata("protocol", "cnp")
						m.body = body
						await self.send(m)
				else:
					body = json.dumps({"protocol": "cnp", "type": "REJECT_PROPOSAL", "task_id": self.task_id})
					if fw:
						await fw.send_through_firewall(dest, body, metadata={"protocol": "cnp"})
					else:
						m = Message(to=dest)
						m.set_metadata("protocol", "cnp")
						m.body = body
						await self.send(m)

			print(f"Accepted proposal from {winner} for task {self.task_id}; waiting up to {self.inform_timeout}s for INFORM")

			# wait for INFORM
			end2 = time.time() + self.inform_timeout
			informed = False
			while time.time() < end2:
				remaining = end2 - time.time()
				msg = await self.receive(timeout=min(0.5, remaining))
				if not msg:
					continue
				try:
					parsed = json.loads(str(msg.body))
				except Exception:
					parsed = None
				if parsed and isinstance(parsed, dict) and parsed.get("protocol") == "cnp" and parsed.get("type") == "INFORM" and parsed.get("task_id") == self.task_id:
					print(f"Received INFORM for {self.task_id}: {parsed}")
					informed = True
					break

			if not informed:
				print(f"Did not receive INFORM for {self.task_id} within timeout")
			# set result and finish
			self.result_future.set_result(informed)

	# Router-level helper to start a CNP round. Returns True if INFORM received, None if aborted
	async def start_cnp(self, task_id: str, task: dict, targets: List[str], proposal_timeout: float = 2.0, inform_timeout: float = 4.0):
		loop = asyncio.get_event_loop()
		fut = loop.create_future()
		beh = self.CNPManagerBehav(task_id, task, targets, proposal_timeout, inform_timeout, fut)
		self.add_behaviour(beh)
		result = await fut
		return result

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
		print(f"Router {str(self.jid)}: node {jid} connected; local_nodes now: {sorted(list(ln))}")

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
		print(f"Failed to start RouterAgent {args.jid}: {e}")
		return

	print("RouterAgent running. Press Ctrl+C to stop.")
	try:
		await spade.wait_until_finished(agent)
	except KeyboardInterrupt:
		print("Stopping RouterAgent...")
	finally:
		await agent.stop()


if __name__ == "__main__":
	spade.run(main())