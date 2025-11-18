"""Firewall behaviours for network traffic filtering and control.

This module implements the firewall logic for both standard nodes and routers,
providing capabilities for blocklisting, rate limiting, and threat detection.
It includes the base FirewallBehaviour and the specialized RouterFirewallBehaviour.
"""

from typing import Optional, Set, Dict, Any
import asyncio
import time
from spade.behaviour import CyclicBehaviour
from spade.message import Message


class FirewallBehaviour(CyclicBehaviour):
    """A simple firewall behaviour that maintains blocklists and filters messages.

    The behaviour provides runtime rule management via control messages and exposes
    helpers to check outbound/inbound messages.

    Attributes:
        blocked_jids (Set[str]): Set of permanently blocked JIDs.
        blocked_keywords (Set[str]): Set of blocked keywords in message body.
        rate_limits (Dict[str, Dict]): Mapping JID -> rate limit config {max_per_sec, count, last_reset}.
        temp_blocks (Dict[str, float]): Mapping JID -> expiry timestamp for temporary blocks.
        suspended_accounts (Set[str]): Set of temporarily suspended JIDs.
    """

    def __init__(self, *args, default_blocked_jids: Optional[Set[str]] = None,
                 default_blocked_keywords: Optional[Set[str]] = None, **kwargs):
        """Initialize firewall with optional default blocklists.

        Args:
            default_blocked_jids (Optional[Set[str]]): Initial set of blocked JIDs.
            default_blocked_keywords (Optional[Set[str]]): Initial set of blocked keywords.
        """
        super().__init__(*args, **kwargs)
        self.blocked_jids = set(default_blocked_jids or [])
        self.blocked_keywords = set(default_blocked_keywords or [])
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.temp_blocks: Dict[str, float] = {}
        self.suspended_accounts: Set[str] = set()
        self._command_lock = asyncio.Lock()

    # Runtime rule management
    def block_jid(self, jid: str):
        """Add JID to permanent blocklist.

        Args:
            jid (str): JID to block permanently.
        """
        self.blocked_jids.add(jid)

    def unblock_jid(self, jid: str):
        """Remove JID from permanent blocklist.

        Args:
            jid (str): JID to unblock.
        """
        self.blocked_jids.discard(jid)

    def block_keyword(self, keyword: str):
        """Add keyword to message body blocklist.

        Args:
            keyword (str): Keyword to block in messages.
        """
        self.blocked_keywords.add(keyword)

    def unblock_keyword(self, keyword: str):
        """Remove keyword from blocklist.

        Args:
            keyword (str): Keyword to unblock.
        """
        self.blocked_keywords.discard(keyword)

    async def allow_message(self, msg: Message) -> bool:
        """Check if message passes firewall rules.

        Flow:
            1. Whitelist monitoring/response agents.
            2. Whitelist control protocols (prevent loops).
            3. Check suspended accounts.
            4. Check temporary blocks (with expiration).
            5. Check rate limits (messages per second).
            6. Check permanent JID blocks.
            7. Check keyword filtering.
            8. Perform threat detection (malware, virus, exploit, etc.).

        Args:
            msg (Message): Incoming message to validate.

        Returns:
            bool: True if message allowed, False if blocked.

        Note:
            When threats are detected, sends an alert to the parent router for monitoring.
        """
        sender = str(msg.sender) if msg.sender is not None else None
        dst = None
        if msg.metadata and "dst" in msg.metadata:
            dst = msg.metadata.get("dst")
        else:
            dst = str(msg.to) if msg.to else None

        # Allow messages from incident response and monitoring agents
        if sender and ("response" in sender or "monitor" in sender):
            return True

        # Don't scan control/alert messages (prevent infinite loops)
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
            "ransomware"
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
        """Send message after applying firewall outbound checks.

        Checks destination against blocklist and body against keywords.
        Updates visualization and resource monitoring.

        Args:
            to (str): Destination JID.
            body (str): Message body text.
            metadata (Optional[dict]): Optional message metadata dict.

        Returns:
            bool: True if sent, False if blocked by firewall.

        Note:
            Adds 0.1s delay to simulate network latency.
            Triggers resource monitor update on successful send.
        """
        # Build a fake message-like object for checking
        fake_msg = Message(to=to)
        # set a fake sender (the agent's jid)
        fake_msg.set_metadata("from", str(self.agent.jid))
        fake_msg.body = body

        # Check destination against blocklist (some firewalls block destinations too)
        if to in self.blocked_jids:
            return False

        for kw in self.blocked_keywords:
            if kw and kw in body:
                return False

        # Emit packet event for visualization
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
            try:
                self.agent._send_adjust = -2.0
            except Exception:
                pass
            if hasattr(self.agent, "_resource_event") and self.agent._resource_event:
                self.agent._resource_event.set()
        except Exception:
            pass
        return True

    async def _handle_control(self, msg: Message):
        """Process firewall control command and send confirmation reply.

        Supported commands:
        - BLOCK_JID:jid
        - UNBLOCK_JID:jid
        - BLOCK_KEY:keyword
        - UNBLOCK_KEY:keyword
        - RATE_LIMIT:jid:10msg/s
        - TEMP_BLOCK:jid:15s
        - SUSPEND_ACCESS:jid
        - UNSUSPEND_ACCESS:jid
        - QUARANTINE_ADVISORY:id
        - LIST

        Args:
            msg (Message): Control message with protocol 'firewall-control'.

        Returns:
            None: Sends a reply message with OK/ERROR status asynchronously.
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
                reply.body = "ERROR Invalid TEMP_BLOCK format (use TEMP_BLOCK:jid:15s)"
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
        """Listen for and process firewall control messages.

        Receives messages with protocol 'firewall-control' and delegates
        to _handle_control(). Other messages are ignored by firewall.

        Timeout:
            1 second per cycle.
        """
        msg = await self.receive(timeout=1)
        if msg:
            # Control messages are those explicitly labeled; others are ignored by firewall
            proto = msg.metadata.get("protocol") if msg.metadata else None
            if proto == "firewall-control":
                await self._handle_control(msg)
            else:
                pass


class RouterFirewallBehaviour(FirewallBehaviour):
    """Firewall behaviour specialized for routers.

    Routers inspect traffic crossing subnet boundaries but allow
    intra-subnet forwarding without re-applying node rules.

    Key differences from base FirewallBehaviour:
    - Uses 'original_sender' metadata (not direct sender).
    - Allows local-to-local forwarding without keyword checks.
    - Reports threats using original sender JID.

    Attributes:
        Inherits all attributes from FirewallBehaviour.
    """

    async def allow_message(self, msg: Message) -> bool:
        """Check if message passes router firewall rules.

        Uses 'original_sender' metadata (set by router) instead of direct sender
        to correctly identify attackers in multi-hop routing.

        Flow:
            1. Extract original_sender from metadata (fallback to direct sender).
            2. Whitelist monitoring/response agents.
            3. Whitelist control protocols.
            4. Check suspended accounts (original_sender).
            5. Check temporary blocks (original_sender).
            6. Check rate limits (original_sender).
            7. Check permanent blocks (original_sender).
            8. Check keyword filtering.
            9. Perform threat detection, and report using original_sender.

        Args:
            msg (Message): Incoming message with metadata.

        Returns:
            bool: True if allowed, False if blocked.
        """
        direct_sender = str(msg.sender) if msg.sender is not None else None
        original_sender = msg.get_metadata("original_sender") if msg.metadata else None
        if not original_sender:
            original_sender = direct_sender  # Fallback se a mensagem for direta

        dst = None
        if msg.metadata and "dst" in msg.metadata:
            dst = msg.metadata.get("dst")
        else:
            dst = str(msg.to) if msg.to else None

        # If direct sender is a monitoring/response agent, allow
        if direct_sender and ("response" in direct_sender or "monitor" in direct_sender):
            return True

        # Don't scan control/alert messages (prevent infinite loops)
        protocol = msg.metadata.get("protocol") if msg.metadata else None
        if protocol in ["firewall-control", "threat-alert", "network-copy"]:
            return True

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

        # CHECK PERMANENT BLOCKS FIRST
        body = (msg.body or "")
        if original_sender and original_sender in self.blocked_jids:
            return False  # Permanently blocked - no need to check threats-

        # Check blocked keywords
        for kw in self.blocked_keywords:
            if kw and kw in body:
                return False

        # Check for threats in message body
        threat_keywords = [
            "malware", "virus", "exploit", "trojan", "worm","ransomware"
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
        """Send message with router-specific firewall rules.

        Allows local-to-local forwarding without keyword checks.
        External sends apply full blocklist verification.

        Flow:
            1. Check if sender and receiver are in local nodes (local-to-local).
            2. If local: Skip keyword checks, simulate latency, notify monitor.
            3. If external: Apply full permanent blocklist check.
            4. If external: Apply keyword check.
            5. Simulate network latency (0.1s).

        Args:
            to (str): Destination JID.
            body (str): Message body.
            metadata (Optional[dict]): Optional metadata dict.

        Returns:
            bool: True if sent, False if blocked.
        """
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