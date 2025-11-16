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
  - BLOCK_JID:<jid> - Permanently block a JID
  - UNBLOCK_JID:<jid> - Remove permanent block
  - BLOCK_KEY:<keyword> - Block messages containing keyword
  - UNBLOCK_KEY:<keyword> - Remove keyword block
  - RATE_LIMIT:<jid>:<rate>msg/s - Throttle messages from JID (e.g., "10msg/s")
  - TEMP_BLOCK:<jid>:<duration>s - Temporary block (e.g., "30s")
  - SUSPEND_ACCESS:<jid> - Suspend account (reversible)
  - UNSUSPEND_ACCESS:<jid> - Restore suspended account
  - QUARANTINE_ADVISORY:<incident_id> - Log quarantine recommendation
  - ADMIN_ALERT:<type>:<incident_id>:<jid> - Alert administrators
  - LIST - List all active rules

The behaviour exposes coroutine helpers:
  - await fw.allow_message(msg) -> bool
  - await fw.send_through_firewall(to, body, metadata=None) -> bool (True if sent)

Note: Node code must call firewall's send_through_firewall for outbound messages to
ensure filtering. The behaviour also actively replies to control messages with a
confirmation.
"""

from typing import Optional, Set, Dict, Any
import asyncio
import time

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

        # Rate limiting: jid -> {max_per_sec, count, last_reset_time}
        self.rate_limits: Dict[str, Dict[str, Any]] = {}

        # Temporary blocks: jid -> expiry_timestamp
        self.temp_blocks: Dict[str, float] = {}

        # Suspended accounts: set of JIDs
        self.suspended_accounts: Set[str] = set()

        # Command lock for thread safety
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

        Checks sender JID and message body keywords. If threats detected,
        reports to router/monitor for incident response.

        Also enforces:
        - Rate limiting (messages per second)
        - Temporary blocks (time-based expiration)
        - Account suspensions (reversible blocks)
        - Permanent JID blocks
        - Keyword filtering
        """
        sender = str(msg.sender) if msg.sender is not None else None
        dst = None
        if msg.metadata and "dst" in msg.metadata:
            dst = msg.metadata.get("dst")
        else:
            dst = str(msg.to) if msg.to else None

        # WHITELIST: Allow messages from incident response and monitoring agents
        if sender and ("response" in sender or "monitor" in sender):
            return True

        # WHITELIST: Don't scan control/alert messages (prevent infinite loops)
        protocol = msg.metadata.get("protocol") if msg.metadata else None
        if protocol in ["firewall-control", "threat-alert", "network-copy"]:
            return True

        # CHECK SUSPENDED ACCOUNTS (reversible block)
        if sender and sender in self.suspended_accounts:
            return False

        # CHECK TEMPORARY BLOCKS (expire after duration)
        if sender and sender in self.temp_blocks:
            if time.time() < self.temp_blocks[sender]:
                return False  # Still blocked
            else:
                # Expired - remove from temp blocks
                del self.temp_blocks[sender]

        # CHECK RATE LIMITS (throttle high-volume senders)
        if sender and sender in self.rate_limits:
            limit_data = self.rate_limits[sender]
            now = time.time()

            # Reset counter every second
            if now - limit_data["last_reset"] >= 1.0:
                limit_data["count"] = 0
                limit_data["last_reset"] = now

            # Increment message count
            limit_data["count"] += 1

            # Check if over limit
            if limit_data["count"] > limit_data["max_per_sec"]:
                return False  # Rate limit exceeded

        # CHECK PERMANENT BLOCKS FIRST (don't waste time analyzing blocked senders)
        body = (msg.body or "")
        if sender and sender in self.blocked_jids:
            return False  # Permanently blocked - no need to check threats

        # Check blocked keywords
        for kw in self.blocked_keywords:
            if kw and kw in body:
                return False

        # Check for threats in message body (only for non-blocked senders)
        threat_keywords = [
            "malware", "virus", "exploit", "trojan", "worm",
            "ransomware", "failed login", "failed_login", "unauthorized"
        ]

        threat_detected = False
        detected_keywords = []
        for kw in threat_keywords:
            if kw in body.lower():
                threat_detected = True
                detected_keywords.append(kw)

        # If threat detected from NEW sender, report to parent router for monitoring
        if threat_detected:
            peers = self.agent.get("peers") or []
            if peers:
                router_jid = peers[0]  # Parent router
                alert_msg = Message(to=router_jid)
                alert_msg.set_metadata("protocol", "threat-alert")
                alert_msg.body = f"THREAT from {sender} to {self.agent.jid}: {', '.join(detected_keywords)} - {body[:100]}"
                await self.send(alert_msg)
                print(f"[FIREWALL {self.agent.jid}] Threat detected from {sender}, reported to {router_jid}")

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

        for kw in self.blocked_keywords:
            if kw and kw in body:
                return False

        # Emit packet event for visualization (node -> router/destination)
        viz = self.agent.get("_visualizer")
        if viz:
            print(f"[FIREWALL] Adding packet: {str(self.agent.jid)} -> {to}")
            viz.add_packet(str(self.agent.jid), to)

        msg = Message(to=to)
        msg.body = body
        if metadata:
            for k, v in metadata.items():
                msg.set_metadata(k, str(v))
        await self.send(msg)

        # Small delay to simulate network latency
        await asyncio.sleep(0.1)

        # notify agent-level resource monitor (if present) about outbound send
        try:
            self.agent._force_pprint = True
            # small one-shot adjustment to base cpu to simulate freeing/doing work
            try:
                # negative adjust reduces the reported base CPU briefly
                self.agent._send_adjust = -2.0
            except Exception:
                pass
            if hasattr(self.agent, "_resource_event") and self.agent._resource_event:
                self.agent._resource_event.set()
        except Exception:
            pass
        return True

    async def _handle_control(self, msg: Message):
        """Process an incoming control message to update rules.

        Control messages must have protocol 'firewall-control' and body with one of
        the supported commands.
        """
        body = (msg.body or "").strip()
        reply = Message(to=str(msg.sender))
        reply.set_metadata("protocol", "firewall-control")

        # BLOCK_JID - Permanent block
        if body.upper().startswith("BLOCK_JID:"):
            jid = body.split(":", 1)[1].strip()
            self.block_jid(jid)
            reply.body = f"OK BLOCKED {jid}"
            await self.send(reply)
            return

        # UNBLOCK_JID - Remove permanent block
        if body.upper().startswith("UNBLOCK_JID:"):
            jid = body.split(":", 1)[1].strip()
            self.unblock_jid(jid)
            reply.body = f"OK UNBLOCKED {jid}"
            await self.send(reply)
            return

        # BLOCK_KEY - Block keyword
        if body.upper().startswith("BLOCK_KEY:"):
            kw = body.split(":", 1)[1].strip()
            self.block_keyword(kw)
            reply.body = f"OK BLOCKED_KEY {kw}"
            await self.send(reply)
            return

        # UNBLOCK_KEY - Remove keyword block
        if body.upper().startswith("UNBLOCK_KEY:"):
            kw = body.split(":", 1)[1].strip()
            self.unblock_keyword(kw)
            reply.body = f"OK UNBLOCKED_KEY {kw}"
            await self.send(reply)
            return

        # RATE_LIMIT - Throttle messages per second
        if body.upper().startswith("RATE_LIMIT:"):
            parts = body.split(":")
            if len(parts) >= 3:
                jid = parts[1].strip()
                rate_str = parts[2].strip().upper().replace("MSG/S", "").strip()
                try:
                    max_per_sec = int(rate_str)
                    self.rate_limits[jid] = {
                        "max_per_sec": max_per_sec,
                        "count": 0,
                        "last_reset": time.time()
                    }
                    reply.body = f"OK RATE_LIMITED {jid} to {max_per_sec} msg/s"
                    print(f"[FIREWALL {self.agent.jid}] Rate limit applied: {jid} -> {max_per_sec} msg/s")
                except ValueError:
                    reply.body = f"ERROR Invalid rate format: {rate_str}"
            else:
                reply.body = "ERROR Invalid RATE_LIMIT format (use RATE_LIMIT:jid:10msg/s)"
            await self.send(reply)
            return

        # TEMP_BLOCK - Temporary block with expiration
        if body.upper().startswith("TEMP_BLOCK:"):
            parts = body.split(":")
            if len(parts) >= 3:
                jid = parts[1].strip()
                duration_str = parts[2].strip().upper().replace("S", "").strip()
                try:
                    duration_sec = int(duration_str)
                    expiry = time.time() + duration_sec
                    self.temp_blocks[jid] = expiry
                    reply.body = f"OK TEMP_BLOCKED {jid} for {duration_sec}s"
                    print(f"[FIREWALL {self.agent.jid}] Temporary block: {jid} for {duration_sec}s")
                except ValueError:
                    reply.body = f"ERROR Invalid duration format: {duration_str}"
            else:
                reply.body = "ERROR Invalid TEMP_BLOCK format (use TEMP_BLOCK:jid:30s)"
            await self.send(reply)
            return

        # SUSPEND_ACCESS - Suspend account (reversible)
        if body.upper().startswith("SUSPEND_ACCESS:"):
            jid = body.split(":", 1)[1].strip()
            self.suspended_accounts.add(jid)
            reply.body = f"OK SUSPENDED {jid}"
            print(f"[FIREWALL {self.agent.jid}] Account suspended: {jid}")
            await self.send(reply)
            return

        # UNSUSPEND_ACCESS - Restore suspended account
        if body.upper().startswith("UNSUSPEND_ACCESS:"):
            jid = body.split(":", 1)[1].strip()
            self.suspended_accounts.discard(jid)
            reply.body = f"OK UNSUSPENDED {jid}"
            print(f"[FIREWALL {self.agent.jid}] Account unsuspended: {jid}")
            await self.send(reply)
            return

        # QUARANTINE_ADVISORY - Log quarantine recommendation (informational)
        if body.upper().startswith("QUARANTINE_ADVISORY:"):
            # Silently acknowledge - nodes could implement isolation procedures here
            reply.body = "OK QUARANTINE_ACKNOWLEDGED"
            await self.send(reply)
            return
            reply.body = f"OK QUARANTINE_ADVISORY logged for {incident_id}"
            await self.send(reply)
            return

        # ADMIN_ALERT - Alert administrators (informational)
        if body.upper().startswith("ADMIN_ALERT:"):
            parts = body.split(":")
            if len(parts) >= 3:
                incident_type = parts[1].strip()
                incident_id = parts[2].strip()
                offender = parts[3].strip() if len(parts) > 3 else "unknown"
                print(f"[FIREWALL {self.agent.jid}] ⚠️  ADMIN ALERT: {incident_type}")
                print(f"[FIREWALL {self.agent.jid}]    Incident: {incident_id}")
                print(f"[FIREWALL {self.agent.jid}]    Offender: {offender}")
                print(f"[FIREWALL {self.agent.jid}]    Action Required: Human review recommended")
                reply.body = f"OK ADMIN_ALERT sent for {incident_id}"
            else:
                print(f"[FIREWALL {self.agent.jid}] ⚠️  ADMIN ALERT: {body}")
                reply.body = "OK ADMIN_ALERT logged"
            await self.send(reply)
            return

        # LIST - Show all active rules
        if body.upper() == "LIST":
            lines = ["BLOCKED_JIDS:"] + list(self.blocked_jids)
            lines += ["BLOCKED_KEYWORDS:"] + list(self.blocked_keywords)
            lines += ["SUSPENDED_ACCOUNTS:"] + list(self.suspended_accounts)
            lines += ["RATE_LIMITS:"] + [f"{jid}: {data['max_per_sec']} msg/s" for jid, data in self.rate_limits.items()]
            lines += ["TEMP_BLOCKS:"] + [f"{jid}: expires {data - time.time():.1f}s" for jid, data in self.temp_blocks.items()]
            reply.body = "\n".join(lines)
            await self.send(reply)
            return

        # Unknown command
        reply.body = f"ERROR Unknown firewall command: {body.split(':')[0]}"
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


class RouterFirewallBehaviour(FirewallBehaviour):
    """Firewall behaviour specialised for routers.

    Routers should inspect traffic coming from or destined to outside the
    local subnet, but allow intra-subnet forwarding without re-applying node
    rules. This class overrides allow_message/send_through_firewall to implement
    that explicit behaviour while keeping the same control-message handling.
    """

    # Em firewall.py

    async def allow_message(self, msg: Message) -> bool:
        """Return True if the message is allowed by the firewall rules.

        Checks sender JID and message body keywords. If threats detected,
        reports to router/monitor for incident response.

        Also enforces:
        - Rate limiting (messages per second)
        - Temporary blocks (time-based expiration)
        - Account suspensions (reversible blocks)
        - Permanent JID blocks
        - Keyword filtering
        """

        # --- INÍCIO DA CORREÇÃO ---
        # O "remetente direto" é quem nos enviou a mensagem (ex: o router)
        direct_sender = str(msg.sender) if msg.sender is not None else None

        # O "remetente original" é quem realmente a escreveu (ex: o atacante)
        # O router adiciona isto aos metadados
        original_sender = msg.get_metadata("original_sender") if msg.metadata else None
        if not original_sender:
            original_sender = direct_sender  # Fallback se a mensagem for direta

        dst = None
        if msg.metadata and "dst" in msg.metadata:
            dst = msg.metadata.get("dst")
        else:
            dst = str(msg.to) if msg.to else None

        # Se for um agente de segurança, confiamos nele.
        if direct_sender and ("response" in direct_sender or "monitor" in direct_sender):
            return True

        # WHITELIST: Don't scan control/alert messages (prevent infinite loops)
        protocol = msg.metadata.get("protocol") if msg.metadata else None
        if protocol in ["firewall-control", "threat-alert", "network-copy"]:
            return True

        # TODAS AS VERIFICAÇÕES DE BLOQUEIO DEVEM USAR O "original_sender"

        # CHECK SUSPENDED ACCOUNTS (reversible block)
        if original_sender and original_sender in self.suspended_accounts:
            return False

        # CHECK TEMPORARY BLOCKS (expire after duration)
        if original_sender and original_sender in self.temp_blocks:
            if time.time() < self.temp_blocks[original_sender]:
                return False  # Still blocked
            else:
                # Expired - remove from temp blocks
                del self.temp_blocks[original_sender]

        # CHECK RATE LIMITS (throttle high-volume senders)
        if original_sender and original_sender in self.rate_limits:
            limit_data = self.rate_limits[original_sender]
            now = time.time()

            # Reset counter every second
            if now - limit_data["last_reset"] >= 1.0:
                limit_data["count"] = 0
                limit_data["last_reset"] = now

            # Increment message count
            limit_data["count"] += 1

            # Check if over limit
            if limit_data["count"] > limit_data["max_per_sec"]:
                return False  # Rate limit exceeded

        # CHECK PERMANENT BLOCKS FIRST (don't waste time analyzing blocked senders)
        body = (msg.body or "")
        if original_sender and original_sender in self.blocked_jids:
            return False  # Permanently blocked - no need to check threats-

        # Check blocked keywords
        for kw in self.blocked_keywords:
            if kw and kw in body:
                return False

        # Check for threats in message body (only for non-blocked senders)
        threat_keywords = [
            "malware", "virus", "exploit", "trojan", "worm",
            "ransomware", "failed login", "failed_login", "unauthorized"
        ]

        threat_detected = False
        detected_keywords = []
        for kw in threat_keywords:
            if kw in body.lower():
                threat_detected = True
                detected_keywords.append(kw)

        # If threat detected from NEW sender, report to parent router for monitoring
        if threat_detected:
            peers = self.agent.get("peers") or []
            if peers:
                router_jid = peers[0]  # Parent router
                alert_msg = Message(to=router_jid)
                alert_msg.set_metadata("protocol", "threat-alert")
                # Usar o original_sender no relatório
                alert_msg.body = f"THREAT from {original_sender} to {self.agent.jid}: {', '.join(detected_keywords)} - {body[:100]}"
                await self.send(alert_msg)
                print(f"[FIREWALL {self.agent.jid}] Threat detected from {original_sender}, reported to {router_jid}")

        return True

    async def send_through_firewall(self, to: str, body: str, metadata: Optional[dict] = None) -> bool:
        # Allow forwarding when both sender (this router) and destination are local
        try:
            local_nodes = self.agent.get("local_nodes") or set()
        except Exception:
            local_nodes = set()
        sender_jid = str(self.agent.jid)
        if local_nodes and sender_jid in local_nodes and to in local_nodes:
            # Emit packet event for visualization (router -> local node)
            viz = self.agent.get("_visualizer")
            if viz:
                print(f"[ROUTER_FIREWALL] Adding packet: {str(self.agent.jid)} -> {to}")
                viz.add_packet(str(self.agent.jid), to)

            msg = Message(to=to)
            msg.body = body
            if metadata:
                for k, v in metadata.items():
                    msg.set_metadata(k, str(v))
            await self.send(msg)

            # Small delay to simulate network latency
            await asyncio.sleep(0.1)

            # notify resource monitor about this local-forward send as well
            try:
                self.agent._force_pprint = True
                try:
                    self.agent._send_adjust = -2.0
                except Exception:
                    pass
                if hasattr(self.agent, "_resource_event") and self.agent._resource_event:
                    self.agent._resource_event.set()
            except Exception:
                pass
            return True

        # For external sends, apply blocklists
        if to in self.blocked_jids:
            return False
        for kw in self.blocked_keywords:
            if kw and kw in body:
                return False
        # Emit packet event for visualization (router -> router or router -> external)
        viz = self.agent.get("_visualizer")
        if viz:
            print(f"[ROUTER_FIREWALL_EXTERNAL] Adding packet: {str(self.agent.jid)} -> {to}")
            viz.add_packet(str(self.agent.jid), to)

        msg = Message(to=to)
        msg.body = body
        if metadata:
            for k, v in metadata.items():
                msg.set_metadata(k, str(v))
        await self.send(msg)

        # Small delay to simulate network latency
        await asyncio.sleep(0.1)

        # notify agent-level resource monitor (if present) about outbound send
        try:
            self.agent._force_pprint = True
            try:
                self.agent._send_adjust = -2.0
            except Exception:
                pass
            if hasattr(self.agent, "_resource_event") and self.agent._resource_event:
                self.agent._resource_event.set()
        except Exception:
            pass
        return True