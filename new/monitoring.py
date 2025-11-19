"""
Monitoring agent for the simulated network.

This agent listens for messages and applies simple heuristics to detect
potentially malicious traffic. On detection it can:
 - Use CNP (Contract Net Protocol) to auction incident response tasks
 - Send CFP to all response agents, evaluate proposals, award to best bidder
 - Optionally instruct node firewalls to block an offending JID directly
"""

import argparse
import asyncio
import datetime
import getpass
from collections import defaultdict, deque
from typing import Deque, Dict, List, Any

import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour, PeriodicBehaviour
from spade.message import Message


def _log(agent_type: str, jid: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class MonitoringAgent(Agent):
    """Agent that monitors messages and generates alerts using CNP."""

    class ResourceBehaviour(PeriodicBehaviour):
        """Periodically updates monitor resource metrics."""
        async def run(self):
            messages_analyzed = self.agent.get("messages_analyzed") or 0
            pending_cfps = self.agent.get("pending_cfps") or {}
            active_auctions = len(pending_cfps)

            base_cpu = 20.0
            base_bw = 10.0
            analysis_cpu = messages_analyzed * 1.5
            analysis_bw = messages_analyzed * 1.0
            auction_cpu = active_auctions * 10.0
            auction_bw = active_auctions * 5.0

            cpu_usage = min(100.0, base_cpu + analysis_cpu + auction_cpu)
            bandwidth_usage = min(100.0, base_bw + analysis_bw + auction_bw)

            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bandwidth_usage)
            self.agent.set("messages_analyzed", 0)

    class CNPInitiatorBehaviour(CyclicBehaviour):
        """Handles CNP initiator protocol."""
        async def on_start(self):
            _log("MonitoringAgent", str(self.agent.jid), "Monitoring behaviour started")
            self.alerted_senders: Dict[str, float] = {}

        async def run(self):
            msg = await self.receive(timeout=1)
            if msg:
                protocol = msg.get_metadata("protocol")
                performative = msg.get_metadata("performative")

                if protocol == "cnp-propose" and performative == "PROPOSE":
                    await self.handle_propose(msg)
                elif protocol == "cnp-inform" and performative == "INFORM":
                    await self.handle_inform(msg)

        async def handle_propose(self, msg: Message):
            incident_id = msg.get_metadata("incident_id")
            score = float(msg.get_metadata("availability_score") or 999.0)
            bidder_jid = str(msg.sender)

            pending = self.agent.get("pending_cfps") or {}

            if incident_id not in pending:
                return

            pending[incident_id]["proposals"].append({
                "bidder_jid": bidder_jid,
                "score": score
            })
            _log("MonitoringAgent", str(self.agent.jid),
                 f"Received proposal from {bidder_jid} for incident {incident_id}: score={score:.2f}")

            self.agent.set("pending_cfps", pending)

            response_jids = self.agent.get("response_jids") or []
            if len(pending[incident_id]["proposals"]) >= len(response_jids):
                await self.evaluate_proposals(incident_id)

        async def evaluate_proposals(self, incident_id: str):
            pending = self.agent.get("pending_cfps") or {}

            if incident_id not in pending:
                return

            incident = pending[incident_id]
            proposals = incident["proposals"]

            if not proposals:
                del pending[incident_id]
                self.agent.set("pending_cfps", pending)
                return

            best = min(proposals, key=lambda p: p["score"])
            winner_jid = best["bidder_jid"]

            _log("MonitoringAgent", str(self.agent.jid),
                 f"AUCTION RESULT: {winner_jid} won incident {incident_id} with score {best['score']:.2f}")

            accept = Message(to=winner_jid)
            accept.set_metadata("protocol", "cnp-accept")
            accept.set_metadata("performative", "ACCEPT_PROPOSAL")
            accept.set_metadata("incident_id", incident_id)
            accept.set_metadata("threat_type", incident["threat_type"])
            accept.set_metadata("offender_jid", incident["offender_jid"])
            # CORREÇÃO: Passar a vítima para o vencedor
            accept.set_metadata("victim_jid", incident["victim_jid"])
            # Pass intensity for probabilistic mitigation
            accept.set_metadata("intensity", str(incident.get("intensity", 5)))

            accept.body = f"Contract awarded for incident {incident_id}"
            await self.send(accept)

            for proposal in proposals:
                if proposal["bidder_jid"] != winner_jid:
                    reject = Message(to=proposal["bidder_jid"])
                    reject.set_metadata("protocol", "cnp-reject")
                    reject.set_metadata("performative", "REJECT_PROPOSAL")
                    reject.set_metadata("incident_id", incident_id)
                    reject.body = f"Proposal rejected for incident {incident_id}"
                    await self.send(reject)

            incident["status"] = "awarded"
            incident["winner"] = winner_jid
            self.agent.set("pending_cfps", pending)

        async def handle_inform(self, msg: Message):
            incident_id = msg.get_metadata("incident_id")
            status = msg.get_metadata("status")
            _log("MonitoringAgent", str(self.agent.jid),
                 f"Incident {incident_id} completed by {msg.sender}: {status}")
            pending = self.agent.get("pending_cfps") or {}
            if incident_id in pending:
                del pending[incident_id]
                self.agent.set("pending_cfps", pending)

    class MonitorBehav(CyclicBehaviour):
        # CORREÇÃO: Janela de 3s para tolerar lag do sistema
        def __init__(self, suspicious_window: int = 3, suspicious_threshold: int = 5, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.window = suspicious_window
            self.threshold = suspicious_threshold

            self.events: dict[str, Deque[float]] = defaultdict(lambda: deque())
            self.suspicious_keyword_events: dict[str, Deque[float]] = defaultdict(lambda: deque())
            self.suspicious_keyword_window: int = 60
            self.suspicious_keyword_threshold: int = 3

            self.high_priority_keywords = [
                "malware", "virus", "exploit", "trojan", "worm", "ransomware",
            ]
            self.low_priority_keywords = [
                "failed login", "failed_login", "unauthorized", 
                "exfiltration", "data_exfiltration", "backdoor", "lateral",
            ]

        async def on_start(self):
            _log("MonitoringAgent", str(self.agent.jid), "Monitoring behaviour started")
            self.alerted_senders: Dict[str, float] = {}

        async def initiate_cnp(self, offender_jid: str, threat_type: str, alert: Dict[str, Any], victim_jid: str = None):
            counter = self.agent.get("incident_counter") or 0
            incident_id = f"incident_{counter}"
            self.agent.set("incident_counter", counter + 1)

            response_jids = self.agent.get("response_jids") or []

            # CORREÇÃO: Garantir string
            victim_str = str(victim_jid) if victim_jid else "unknown"

            _log("MonitoringAgent", str(self.agent.jid),
                 f"Starting CNP auction for incident {incident_id}: {threat_type} from {offender_jid} targeting {victim_str}")

            # Extract intensity from alert
            intensity_value = alert.get("intensity", 5)

            pending = self.agent.get("pending_cfps") or {}
            pending[incident_id] = {
                "threat_type": threat_type,
                "offender_jid": offender_jid,
                "victim_jid": victim_str,
                "alert": alert,
                "intensity": intensity_value,
                "proposals": [],
                "status": "waiting",
                "deadline": asyncio.get_event_loop().time() + 2.0,
                "cfp_time": datetime.datetime.now().isoformat()
            }
            self.agent.set("pending_cfps", pending)

            for resp_jid in response_jids:
                cfp = Message(to=resp_jid)
                cfp.set_metadata("protocol", "cnp-cfp")
                cfp.set_metadata("performative", "CFP")
                cfp.set_metadata("incident_id", str(incident_id))
                cfp.set_metadata("threat_type", str(threat_type))
                cfp.set_metadata("severity", "high")
                cfp.set_metadata("offender_jid", str(offender_jid))
                cfp.set_metadata("victim_jid", victim_str)
                cfp.body = f"CFP for incident {incident_id}: {threat_type} from {offender_jid}"
                await self.send(cfp)
                _log("MonitoringAgent", str(self.agent.jid), f"Sent CFP to {resp_jid}")

        async def process_message(self, msg: Message):
            now = asyncio.get_event_loop().time()
            protocol = msg.get_metadata("protocol")

            if protocol == "network-copy":
                sender = msg.get_metadata("original_sender")
                if not sender:
                    sender = str(msg.sender)
            else:
                sender = str(msg.sender) if msg.sender else "unknown"

            if not sender: sender = "unknown"
            sender = str(sender)

            # Tentar extrair vítima do cabeçalho
            dst = msg.get_metadata("dst")
            if not dst:
                dst = str(msg.to)

            if "monitor" in dst:
                victim_jid = "unknown"
            else:
                victim_jid = dst

            # Whitelist
            if "response" in sender or "monitor" in sender:
                return

            # Silencing
            if sender in self.alerted_senders:
                if now < self.alerted_senders[sender]:
                    return
                else:
                    del self.alerted_senders[sender]

            body = (msg.body or "").strip()
            body_lower = body.lower()

            # CORREÇÃO: Ignorar tráfego benigno
            if "pong" in body_lower or "response:" in body_lower:
                return

            self.agent.set("messages_analyzed", (self.agent.get("messages_analyzed") or 0) + 1)
            _log("MonitoringAgent", str(self.agent.jid), f"Checking message from {sender}")

            suspicious = False
            reasons = []

            # 1. DDoS Check
            dq = self.events[sender]
            dq.append(now)
            while dq and dq[0] < now - self.window:
                dq.popleft()

            if len(dq) >= self.threshold:
                suspicious = True
                reasons.append(f"rate:{len(dq)} in {self.window}s")

            # 2. Keywords
            if not suspicious:
                for kw in self.high_priority_keywords:
                    if kw in body_lower:
                        suspicious = True
                        reasons.append(f"high_priority_keyword:{kw}")
                        break

            if not suspicious:
                for kw in self.low_priority_keywords:
                    if kw in body_lower:
                        kw_dq = self.suspicious_keyword_events[sender]
                        kw_dq.append(now)
                        while kw_dq and kw_dq[0] < now - self.suspicious_keyword_window:
                            kw_dq.popleft()

                        if len(kw_dq) >= self.suspicious_keyword_threshold:
                            suspicious = True
                            reasons.append(f"keyword_rate:{kw} ({len(kw_dq)} in {self.suspicious_keyword_window}s)")
                        break

            # CORREÇÃO: Extrair vítima do corpo da mensagem (se presente)
            if "target:" in body_lower:
                try:
                    start_index = body_lower.find("target:") + len("target:")
                    end_index = body.find(' ', start_index)
                    if end_index == -1: end_index = len(body_lower)
                    extracted = body_lower[start_index:end_index].strip()
                    if extracted:
                        victim_jid = extracted
                except:
                    pass

            if suspicious:
                # Probabilistic detection - sophisticated attackers may evade detection
                import random
                
                # Extract attacker intensity to adjust detection probability
                attacker_intensity = msg.get_metadata("attacker_intensity")
                intensity_value = int(attacker_intensity) if attacker_intensity else 5
                
                # Calculate detection probability based on threat indicators AND attacker skill
                # More reasons = higher detection, higher intensity = lower detection
                base_detection_rate = 60  # Base 60% chance
                detection_bonus = len(reasons) * 15  # +15% per reason
                intensity_penalty = intensity_value * 5  # -5% per intensity level
                detection_rate = min(95, max(20, base_detection_rate + detection_bonus - intensity_penalty))
                
                if random.randint(1, 100) > detection_rate:
                    _log("MonitoringAgent", str(self.agent.jid),
                         f"[DETECTION EVADED] Sophisticated attacker evaded detection - {sender} (intensity={intensity_value}, detection rate: {detection_rate}%)")
                    return  # Attack not detected this time
                
                if sender not in self.alerted_senders:
                    self.alerted_senders[sender] = now + 15.0
                else:
                    return

                # Extract intensity from message metadata if available
                attacker_intensity = msg.get_metadata("attacker_intensity")
                intensity_value = int(attacker_intensity) if attacker_intensity else 5

                alert = {
                    "time": datetime.datetime.now().isoformat(),
                    "sender": sender,
                    "body": body,
                    "reasons": reasons,
                    "victim": victim_jid,
                    "intensity": intensity_value
                }
                _log("MonitoringAgent", str(self.agent.jid), f"[ALERT] {alert}")

                threat_type = "unknown"
                proto = msg.get_metadata("protocol")
                if proto == "malware-infection": threat_type = "malware"
                elif any(r.startswith("rate:") for r in reasons): threat_type = "ddos"
                elif any(r.startswith("keyword_rate:") for r in reasons): threat_type = "insider_threat"
                elif any(r.startswith("high_priority_keyword:") for r in reasons): threat_type = "malware"

                response_jids = self.agent.get("response_jids") or []
                if response_jids:
                    await self.initiate_cnp(sender, threat_type, alert, victim_jid)
                else:
                    resp_jid = self.agent.get("response_jid")
                    if resp_jid:
                        m = Message(to=resp_jid)
                        m.set_metadata("protocol", "monitoring-alert")
                        m.body = f"ALERT {alert}"
                        await self.send(m)

        async def run(self):
            msg = await self.receive(timeout=1)
            if msg:
                protocol = msg.get_metadata("protocol")

                # Ignorar mensagens CNP
                if protocol in ["cnp-cfp", "cnp-propose", "cnp-accept", "cnp-reject", "cnp-inform", "monitoring-alert", "threat-intel-update"]:
                    return

                if protocol == "network-copy":
                    try:
                        await self.process_message(msg)
                    except Exception as e:
                        _log("MonitoringAgent", str(self.agent.jid), f"ERROR processing network-copy: {e}")
                    return

                elif protocol == "threat-alert":
                    try:
                        # Extract offender and victim from metadata (node self-detection)
                        offender_jid = msg.get_metadata("offender") or "unknown"
                        victim_jid = msg.get_metadata("dst") or "unknown"
                        
                        # If metadata extraction failed, try parsing body (firewall alerts)
                        if offender_jid == "unknown" or victim_jid == "unknown":
                            parts = msg.body.split(":", 1)
                            if len(parts) == 2:
                                header = parts[0]
                                # Parse "THREAT from X to Y" format
                                if "from " in header and " to " in header:
                                    from_part = header.split("from ")[1]
                                    offender_match = from_part.split(" to ")[0].strip()
                                    victim_match = from_part.split(" to ")[1].strip()
                                    
                                    if offender_jid == "unknown":
                                        offender_jid = offender_match
                                    if victim_jid == "unknown":
                                        victim_jid = victim_match

                        alert_body = msg.body.lower()
                        threat_type = "malware"
                        for kw in self.low_priority_keywords:
                            if kw in alert_body: threat_type = "insider_threat"; break

                        alert = {
                            "time": datetime.datetime.now().isoformat(),
                            "sender": offender_jid,
                            "body": msg.body,
                            "reasons": ["firewall-detected-threat"]
                        }
                        await self.initiate_cnp(offender_jid, threat_type, alert, victim_jid)
                    except Exception as e:
                        _log("MonitoringAgent", str(self.agent.jid), f"Error parsing threat alert: {e}")
                    return
                else:
                    try:
                        await self.process_message(msg)
                    except:
                        pass

    async def setup(self):
        _log("MonitoringAgent", str(self.jid), "starting...")
        self.set("cpu_usage", 20.0)
        self.set("bandwidth_usage", 10.0)
        self.set("messages_analyzed", 0)
        self.set("pending_cfps", {})
        self.set("incident_counter", 0)

        self.add_behaviour(self.ResourceBehaviour(period=2.0))
        self.add_behaviour(self.MonitorBehav())

        response_jids = self.get("response_jids") or []
        if response_jids:
            self.add_behaviour(self.CNPInitiatorBehaviour())
            _log("MonitoringAgent", str(self.jid), f"CNP enabled with {len(response_jids)} response agents")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Monitoring agent JID")
    parser.add_argument("--password", required=False, help="Agent password")
    parser.add_argument("--nodes", default="", help="Comma-separated node JIDs")
    parser.add_argument("--response", default="", help="Comma-separated response agent JIDs")
    parser.add_argument("--auto-block", action="store_true", help="If set, send BLOCK_JID commands")
    parser.add_argument("--window", type=int, default=3, help="Time window in seconds")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold count")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass()
    nodes = [p.strip() for p in args.nodes.split(',') if p.strip()]
    response_jids = [p.strip() for p in args.response.split(',') if p.strip()]

    agent = MonitoringAgent(args.jid, passwd)
    agent.set("nodes_to_notify", nodes)
    agent.set("response_jids", response_jids)
    agent.set("auto_block", bool(args.auto_block))

    try:
        await agent.start(auto_register=True)
    except Exception as e:
        _log("MonitoringAgent", args.jid, f"Failed to start: {e}")
        return

    for b in agent.behaviours.values():
        if isinstance(b, MonitoringAgent.MonitorBehav):
            b.window = args.window
            b.threshold = args.threshold

    _log("MonitoringAgent", args.jid, "running. Press Ctrl+C to stop")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        _log("MonitoringAgent", args.jid, "Stopping...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    spade.run(main())