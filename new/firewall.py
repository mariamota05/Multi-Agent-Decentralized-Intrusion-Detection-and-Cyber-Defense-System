"""
Firewall behaviour for SPADE agents.

Usage:
  from new.firewall import FirewallBehaviour
  fw = FirewallBehaviour()
  self.add_behaviour(fw)
  # optionally store reference
  self.set("firewall", fw)

The behaviour listens for control messages with protocol 'firewall-control' to modify rules
at runtime. Supported control commands (message body):
  - BLOCK_JID:<jid>
  - UNBLOCK_JID:<jid>
  - BLOCK_KEY:<keyword>
  - UNBLOCK_KEY:<keyword>
  - LIST

The behaviour exposes coroutine helpers:
  - await fw.allow_message(msg) -> bool
  - await fw.send_through_firewall(to, body, metadata=None) -> bool (True if sent)

Note: Node code must call firewall's send_through_firewall for outbound messages to
ensure filtering. The behaviour also actively replies to control messages with a
confirmation.
"""

from typing import Optional, Set
import asyncio

from spade.behaviour import CyclicBehaviour
from spade.message import Message


class FirewallBehaviour(CyclicBehaviour):
	"""A simple firewall behaviour that maintains blocklists and filters messages.

	The behaviour does two things:
	  - Provides runtime rule management via control messages (protocol 'firewall-control').
	  - Exposes helpers to check outbound/inbound messages and to send messages through
		the firewall (so NodeAgent can use it to guard outgoing traffic).
	"""

	def __init__(self, *args, default_blocked_jids: Optional[Set[str]] = None,
				 default_blocked_keywords: Optional[Set[str]] = None, **kwargs):
		super().__init__(*args, **kwargs)
		self.blocked_jids = set(default_blocked_jids or [])
		self.blocked_keywords = set(default_blocked_keywords or [])
		# small queue for requests from other behaviours (optional)
		self._command_lock = asyncio.Lock()

	# Runtime rule management
	def block_jid(self, jid: str):
		self.blocked_jids.add(jid)

	def unblock_jid(self, jid: str):
		self.blocked_jids.discard(jid)

	def block_keyword(self, keyword: str):
		self.blocked_keywords.add(keyword)

	def unblock_keyword(self, keyword: str):
		self.blocked_keywords.discard(keyword)

	async def allow_message(self, msg: Message) -> bool:
		"""Return True if the message is allowed by the firewall rules.

		Checks sender JID and message body keywords.
		"""
		# Node/workstation firewall: always inspect incoming messages and apply
		# blocklists and keyword filters. Nodes should not bypass checks for
		# intra-subnet traffic.
		sender = str(msg.sender) if msg.sender is not None else None
		# attempt to determine destination from metadata or 'to'
		dst = None
		if msg.metadata and "dst" in msg.metadata:
			dst = msg.metadata.get("dst")
		else:
			dst = str(msg.to) if msg.to else None

		# If sender is explicitly blocked, deny
		if sender and sender in self.blocked_jids:
			return False
		body = (msg.body or "")
		for kw in self.blocked_keywords:
			if kw and kw in body:
				return False
		return True

	async def send_through_firewall(self, to: str, body: str, metadata: Optional[dict] = None) -> bool:
		"""Helper used by other behaviours to send messages via the firewall.

		Returns True if the message was sent, False if blocked.
		"""
		# Build a fake message-like object for checking
		fake_msg = Message(to=to)
		# set a fake sender (the agent's jid)
		fake_msg.set_metadata("from", str(self.agent.jid))
		fake_msg.body = body

		# Check destination against blocklist (some firewalls block destinations too)
		# We'll treat blocked_jids as either sender or receiver to be simple
		if to in self.blocked_jids:
			return False

		# Node/workstation firewall: apply blocklists for outbound sends as well.
		# No special bypass behavior here.
		if to in self.blocked_jids:
			return False

		for kw in self.blocked_keywords:
			if kw and kw in body:
				return False

		msg = Message(to=to)
		msg.body = body
		if metadata:
			for k, v in metadata.items():
				msg.set_metadata(k, str(v))
		await self.send(msg)
		return True


class RouterFirewallBehaviour(FirewallBehaviour):
	"""Firewall behaviour specialised for routers.

	Routers should inspect traffic coming from or destined to outside the
	local subnet, but allow intra-subnet forwarding without re-applying node
	rules. This class overrides allow_message/send_through_firewall to implement
	that explicit behaviour while keeping the same control-message handling.
	"""

	async def allow_message(self, msg: Message) -> bool:
		# Determine sender and destination
		sender = str(msg.sender) if msg.sender is not None else None
		dst = None
		if msg.metadata and "dst" in msg.metadata:
			dst = msg.metadata.get("dst")
		else:
			dst = str(msg.to) if msg.to else None

		try:
			local_nodes = self.agent.get("local_nodes") or set()
		except Exception:
			local_nodes = set()

		# If both endpoints are local to this router, allow without blocking
		if sender and dst and local_nodes and sender in local_nodes and dst in local_nodes:
			return True

		# Otherwise apply regular blocklist/keyword checks
		if sender and sender in self.blocked_jids:
			return False
		body = (msg.body or "")
		for kw in self.blocked_keywords:
			if kw and kw in body:
				return False
		return True

	async def send_through_firewall(self, to: str, body: str, metadata: Optional[dict] = None) -> bool:
		# Allow forwarding when both sender (this router) and destination are local
		try:
			local_nodes = self.agent.get("local_nodes") or set()
		except Exception:
			local_nodes = set()
		sender_jid = str(self.agent.jid)
		if local_nodes and sender_jid in local_nodes and to in local_nodes:
			msg = Message(to=to)
			msg.body = body
			if metadata:
				for k, v in metadata.items():
					msg.set_metadata(k, str(v))
			await self.send(msg)
			return True

		# For external sends, apply blocklists
		if to in self.blocked_jids:
			return False
		for kw in self.blocked_keywords:
			if kw and kw in body:
				return False
		msg = Message(to=to)
		msg.body = body
		if metadata:
			for k, v in metadata.items():
				msg.set_metadata(k, str(v))
		await self.send(msg)
		return True

	async def _handle_control(self, msg: Message):
		"""Process an incoming control message to update rules.

		Control messages must have protocol 'firewall-control' and body with one of
		the supported commands.
		"""
		body = (msg.body or "").strip()
		reply = Message(to=str(msg.sender))
		reply.set_metadata("protocol", "firewall-control")

		if body.upper().startswith("BLOCK_JID:"):
			jid = body.split(":", 1)[1].strip()
			self.block_jid(jid)
			reply.body = f"OK BLOCKED {jid}"
			await self.send(reply)
			return

		if body.upper().startswith("UNBLOCK_JID:"):
			jid = body.split(":", 1)[1].strip()
			self.unblock_jid(jid)
			reply.body = f"OK UNBLOCKED {jid}"
			await self.send(reply)
			return

		if body.upper().startswith("BLOCK_KEY:"):
			kw = body.split(":", 1)[1].strip()
			self.block_keyword(kw)
			reply.body = f"OK BLOCKED_KEY {kw}"
			await self.send(reply)
			return

		if body.upper().startswith("UNBLOCK_KEY:"):
			kw = body.split(":", 1)[1].strip()
			self.unblock_keyword(kw)
			reply.body = f"OK UNBLOCKED_KEY {kw}"
			await self.send(reply)
			return

		if body.upper() == "LIST":
			lines = ["BLOCKED_JIDS:"] + list(self.blocked_jids) + ["BLOCKED_KEYWORDS:"] + list(self.blocked_keywords)
			reply.body = "\n".join(lines)
			await self.send(reply)
			return

		# Unknown command
		reply.body = "ERROR Unknown firewall command"
		await self.send(reply)

	async def run(self):
		# Listen for incoming control messages and reply; otherwise idle
		msg = await self.receive(timeout=1)
		if msg:
			# Control messages are those explicitly labeled; others are ignored by firewall
			proto = msg.metadata.get("protocol") if msg.metadata else None
			if proto == "firewall-control":
				await self._handle_control(msg)
			else:
				# not a control message — the firewall doesn't 'deliver' messages to the
				# agent by itself; NodeAgent's RecvBehav will receive messages. The
				# firewall can be used proactively for sending and for runtime rule updates.
				pass

