"""
Monitoring agent for the simulated network.

This agent listens for messages and applies simple heuristics to detect
potentially malicious traffic. On detection it can:
 - Use CNP (Contract Net Protocol) to auction incident response tasks
 - Send CFP to all response agents, evaluate proposals, award to best bidder
 - Optionally instruct node firewalls to block an offending JID directly

Heuristics implemented:
 - Keyword blacklist scanning
 - Rate-based detection for repeated suspicious messages (e.g., repeated failed login)
 - DDoS spike detection (high message volume from single source)

CNP Protocol (when response agents configured):
 1. Monitor detects threat and sends CFP to all response agents
 2. Response agents send PROPOSE with availability scores
 3. Monitor evaluates proposals and sends ACCEPT_PROPOSAL to best bidder
 4. Winner executes mitigation and sends INFORM with results

Usage example:
  python new/monitoring.py --jid monitor@localhost --password secret --nodes node1@localhost,node2@localhost --response response1@localhost,response2@localhost

Notes:
 - SPADE and a running XMPP server are required.
 - Nodes should forward or send copies of traffic to the monitor JID for it to inspect
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
    """Agent that monitors messages and generates alerts using CNP.

    Key configuration stored in agent attributes:
      - response_jids: List of response agent JIDs for CNP auctions
      - pending_cfps: Dict tracking active CNP auctions
      - incident_counter: Counter for generating unique incident IDs
      - cpu_usage: Current CPU usage percentage (updated by ResourceBehaviour)
      - bandwidth_usage: Current bandwidth usage percentage (updated by ResourceBehaviour)
      - messages_analyzed: Counter for messages analyzed (used to calculate resource load)
    """

    class ResourceBehaviour(PeriodicBehaviour):
        """Periodically updates monitor resource metrics based on analysis and CNP activity."""

        async def run(self):
            # Get current metrics
            messages_analyzed = self.agent.get("messages_analyzed") or 0
            pending_cfps = self.agent.get("pending_cfps") or {}
            active_auctions = len(pending_cfps)

            # Base load for monitoring operation
            base_cpu = 20.0  # Traffic analysis is CPU-intensive
            base_bw = 10.0  # Receiving copies of all network traffic

            # Additional load based on analysis workload
            analysis_cpu = messages_analyzed * 1.5
            analysis_bw = messages_analyzed * 1.0

            # Additional load based on active CNP auctions
            auction_cpu = active_auctions * 10.0  # Each auction requires proposal evaluation
            auction_bw = active_auctions * 5.0  # CFP broadcasts and proposal collection

            # Calculate total usage (capped at 100%)
            cpu_usage = min(100.0, base_cpu + analysis_cpu + auction_cpu)
            bandwidth_usage = min(100.0, base_bw + analysis_bw + auction_bw)

            # Update agent state
            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bandwidth_usage)

            # Reset message counter for next period
            self.agent.set("messages_analyzed", 0)

    class CNPInitiatorBehaviour(CyclicBehaviour):
        """
        Handles CNP initiator protocol for incident response auctions:
        1. Receives PROPOSE messages from response agents
        2. Evaluates proposals and selects best bidder
        3. Sends ACCEPT_PROPOSAL to winner, REJECT_PROPOSAL to others
        4. Receives INFORM with results
        """

        async def on_start(self):
            _log("MonitoringAgent", str(self.agent.jid), "Monitoring behaviour started")
            # Adicionar esta linha
            self.alerted_senders: Dict[str, float] = {}  # Mapeia sender ->_expiry_time

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
            """Collect proposal and evaluate when deadline reached"""
            incident_id = msg.get_metadata("incident_id")
            score = float(msg.get_metadata("availability_score") or 999.0)
            bidder_jid = str(msg.sender)

            pending = self.agent.get("pending_cfps") or {}

            if incident_id not in pending:
                _log("MonitoringAgent", str(self.agent.jid),
                     f"Received late proposal from {bidder_jid} for incident {incident_id}")
                return

            # Add proposal to incident
            pending[incident_id]["proposals"].append({
                "bidder_jid": bidder_jid,
                "score": score
            })

            _log("MonitoringAgent", str(self.agent.jid),
                 f"Received proposal from {bidder_jid} for incident {incident_id}: score={score:.2f}")

            self.agent.set("pending_cfps", pending)

            # Evaluate immediately if we have all expected proposals
            response_jids = self.agent.get("response_jids") or []
            if len(pending[incident_id]["proposals"]) >= len(response_jids):
                await self.evaluate_proposals(incident_id)

        async def evaluate_proposals(self, incident_id: str):
            """Select best proposal and award contract"""
            pending = self.agent.get("pending_cfps") or {}

            if incident_id not in pending:
                return

            incident = pending[incident_id]
            proposals = incident["proposals"]

            if not proposals:
                _log("MonitoringAgent", str(self.agent.jid),
                     f"No proposals received for incident {incident_id}")
                del pending[incident_id]
                self.agent.set("pending_cfps", pending)
                return

            # Select best proposal (lowest score = most available)
            best = min(proposals, key=lambda p: p["score"])
            winner_jid = best["bidder_jid"]

            _log("MonitoringAgent", str(self.agent.jid),
                 f"AUCTION RESULT: {winner_jid} won incident {incident_id} with score {best['score']:.2f}")

            # Send ACCEPT_PROPOSAL to winner
            accept = Message(to=winner_jid)
            accept.set_metadata("protocol", "cnp-accept")
            accept.set_metadata("performative", "ACCEPT_PROPOSAL")
            accept.set_metadata("incident_id", incident_id)
            accept.set_metadata("threat_type", incident["threat_type"])
            accept.set_metadata("offender_jid", incident["offender_jid"])
            accept.body = f"Contract awarded for incident {incident_id}"
            await self.send(accept)

            # Send REJECT_PROPOSAL to losers
            for proposal in proposals:
                if proposal["bidder_jid"] != winner_jid:
                    reject = Message(to=proposal["bidder_jid"])
                    reject.set_metadata("protocol", "cnp-reject")
                    reject.set_metadata("performative", "REJECT_PROPOSAL")
                    reject.set_metadata("incident_id", incident_id)
                    reject.body = f"Proposal rejected for incident {incident_id}"
                    await self.send(reject)

            # Update incident status
            incident["status"] = "awarded"
            incident["winner"] = winner_jid
            self.agent.set("pending_cfps", pending)

        async def handle_inform(self, msg: Message):
            """Receive completion notification from response agent"""
            incident_id = msg.get_metadata("incident_id")
            status = msg.get_metadata("status")

            _log("MonitoringAgent", str(self.agent.jid),
                 f"Incident {incident_id} completed by {msg.sender}: {status}")

            # Remove from pending
            pending = self.agent.get("pending_cfps") or {}
            if incident_id in pending:
                del pending[incident_id]
                self.agent.set("pending_cfps", pending)

    class MonitorBehav(CyclicBehaviour):
        # --- INÍCIO DA MODIFICAÇÃO (INIT) ---
        def __init__(self, suspicious_window: int = 10, suspicious_threshold: int = 5, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Limites para DDoS/Rate (já existentes)
            self.window = suspicious_window  # ex: 10s
            self.threshold = suspicious_threshold  # ex: 5 msgs

            # Dicionário de "memória" para DDoS/rate
            self.events: dict[str, Deque[float]] = defaultdict(lambda: deque())

            # --- NOVAS ADIÇÕES PARA RESPOSTA PROPORCIONAL ---
            # Dicionário de "memória" para palavras-chave suspeitas (ex: failed login)
            self.suspicious_keyword_events: dict[str, Deque[float]] = defaultdict(lambda: deque())
            # Limites para logins falhados (3 tentativas em 60 segundos)
            self.suspicious_keyword_window: int = 60
            self.suspicious_keyword_threshold: int = 3

            # Palavras-chave de alerta imediato (Risco Alto)
            self.high_priority_keywords = [
                "malware",
                "virus",
                "exploit",
                # "attack" removida por ser genérica e causar conflito
                "trojan",
                "worm",
                "ransomware",
            ]
            # Palavras-chave de alerta com "memória" (Risco Médio/Baixo)
            self.low_priority_keywords = [
                "failed login",
                "failed_login",
                "unauthorized",
            ]
            # --- FIM DAS ADIÇÕES (INIT) ---

        async def on_start(self):
            _log("MonitoringAgent", str(self.agent.jid), "Monitoring behaviour started")
            # Mapeia sender -> expiry_time (lógica de silenciamento já existente)
            self.alerted_senders: Dict[str, float] = {}

        # --- INÍCIO DA MODIFICAÇÃO (PROCESS_MESSAGE) ---
        async def process_message(self, msg: Message):
            now = asyncio.get_event_loop().time()
            protocol = msg.get_metadata("protocol")

            # Lógica de 'original_sender' (já existente)
            if protocol == "network-copy":
                sender = msg.get_metadata("original_sender")
                if not sender:
                    sender = str(msg.sender)
            else:
                sender = str(msg.sender) if msg.sender else "unknown"

            if not sender:
                sender = "unknown"

            # "LISTA BRANCA" DE SEGURANÇA (já existente)
            if "response" in sender or "monitor" in sender:
                _log("MonitoringAgent", str(self.agent.jid), f"Ignoring whitelisted message from {sender}")
                return

            # IGNORAR ALERTAS REPETIDOS (lógica de silenciamento já existente)
            if sender in self.alerted_senders:
                if now < self.alerted_senders[sender]:
                    _log("MonitoringAgent", str(self.agent.jid), f"Ignoring already-alerted sender {sender}")
                    return  # Ignorar, a mitigação já está (supostamente) ativa
                else:
                    # O silenciamento expirou, remover
                    del self.alerted_senders[sender]
            # --- FIM DO BLOCO DE SILENCIAMENTO ---

            body = (msg.body or "").lower()

            self.agent.set("messages_analyzed", (self.agent.get("messages_analyzed") or 0) + 1)
            _log("MonitoringAgent", str(self.agent.jid), f"Checking message from {sender}")

            suspicious = False
            reasons = []

            # 1. VERIFICAR A TAXA DE MENSAGENS (DDoS) (lógica já existente)
            dq = self.events[sender]
            dq.append(now)
            # Purge old events
            while dq and dq[0] < now - self.window:
                dq.popleft()

            if len(dq) >= self.threshold:
                suspicious = True
                reasons.append(f"rate:{len(dq)} in {self.window}s")

            # --- LÓGICA DE KEYWORD MODIFICADA ---
            # 2. VERIFICAR PALAVRAS-CHAVE DE RISCO ALTO (Alerta Imediato)
            if not suspicious:  # Só verifica se já não for suspeito
                for kw in self.high_priority_keywords:
                    if kw in body:
                        suspicious = True
                        reasons.append(f"high_priority_keyword:{kw}")
                        break  # Encontrámos uma, não precisamos de procurar mais

            # 3. VERIFICAR PALAVRAS-CHAVE DE RISCO BAIXO (Alerta com "Memória")
            if not suspicious:  # Só verifica se ainda não for suspeito
                for kw in self.low_priority_keywords:
                    if kw in body:
                        # Encontrámos uma palavra-chave de risco baixo. Não disparamos já.
                        # Adicionamos ao balde de "memória" desse sender.
                        kw_dq = self.suspicious_keyword_events[sender]
                        kw_dq.append(now)

                        # Limpar eventos antigos
                        while kw_dq and kw_dq[0] < now - self.suspicious_keyword_window:
                            kw_dq.popleft()

                        # Agora, verificamos se o limite foi atingido
                        if len(kw_dq) >= self.suspicious_keyword_threshold:
                            suspicious = True
                            reasons.append(f"keyword_rate:{kw} ({len(kw_dq)} in {self.suspicious_keyword_window}s)")
                        else:
                            # Registar a tentativa, mas não disparar o alarme
                            _log("MonitoringAgent", str(self.agent.jid),
                                 f"Low-priority keyword '{kw}' from {sender} detected. Count: {len(kw_dq)}/{self.suspicious_keyword_threshold}")

                        break  # Processámos a primeira que encontrámos
            # --- FIM DA LÓGICA MODIFICADA ---

            if suspicious:
                # Lógica de silenciamento (já existente)
                if sender not in self.alerted_senders:
                    # Silenciar este 'sender' por 15 segundos
                    self.alerted_senders[sender] = now + 15.0
                    _log("MonitoringAgent", str(self.agent.jid), f"Muting sender {sender} for 15 seconds.")
                else:
                    _log("MonitoringAgent", str(self.agent.jid),
                         f"Check completed for {sender}. Suspicious=True (already muted).")
                    return  # Não iniciar um novo leilão

                ts = datetime.datetime.now().isoformat()
                alert = {
                    "time": ts,
                    "sender": sender,
                    "body": msg.body,
                    "reasons": reasons,
                }
                _log("MonitoringAgent", str(self.agent.jid), f"[ALERT] {alert}")

                # --- LÓGICA DE CLASSIFICAÇÃO DE AMEAÇA MELHORADA ---
                threat_type = "unknown"
                protocol = copy_metadata.get("protocol") if copy_metadata else None
                
                # Check for malware infection protocol
                if protocol == "malware-infection":
                    threat_type = "malware"
                # Usar startswith() para evitar que "rate:" corresponda a "keyword_rate:"
                elif any(r.startswith("rate:") for r in reasons):
                    threat_type = "ddos"
                elif any(r.startswith("keyword_rate:") for r in reasons):
                    # Se foi a taxa de keywords que disparou (ex: failed login)
                    threat_type = "insider_threat"
                elif any(r.startswith("high_priority_keyword:") for r in reasons):
                    # Se foi uma keyword de alta prioridade
                    threat_type = "malware"

                response_jids = self.agent.get("response_jids") or []
                if response_jids:
                    await self.initiate_cnp(sender, threat_type, alert)
                else:
                    # ... (código de fallback, permanece igual) ...
                    resp_jid = self.agent.get("response_jid")
                    if resp_jid:
                        m = Message(to=resp_jid)
                        m.set_metadata("protocol", "monitoring-alert")
                        m.body = f"ALERT {alert}"
                        await self.send(m)
                        _log("MonitoringAgent", str(self.agent.jid), f"Sent alert to response agent {resp_jid}")

                # ... (código de auto-block, permanece igual) ...
                if self.agent.get("auto_block"):
                    offender = sender
                    nodes = self.agent.get("nodes_to_notify") or []
                    for node in nodes:
                        ctrl = Message(to=node)
                        ctrl.set_metadata("protocol", "firewall-control")
                        ctrl.body = f"BLOCK_JID:{offender}"
                        await self.send(ctrl)
                        _log("MonitoringAgent", str(self.agent.jid),
                             f"Sent firewall-control BLOCK_JID for {offender} to {node}")

            _log("MonitoringAgent", str(self.agent.jid),
                 f"Check completed for {sender}. Suspicious={suspicious}. Reasons={reasons}")

        # --- FIM DA MODIFICAÇÃO (PROCESS_MESSAGE) ---

        async def initiate_cnp(self, offender_jid: str, threat_type: str, alert: Dict[str, Any]):
            """Start CNP auction for incident response"""
            # Generate simple incident ID using counter
            counter = self.agent.get("incident_counter") or 0
            incident_id = f"incident_{counter}"
            self.agent.set("incident_counter", counter + 1)

            response_jids = self.agent.get("response_jids") or []

            _log("MonitoringAgent", str(self.agent.jid),
                 f"Starting CNP auction for incident {incident_id}: {threat_type} from {offender_jid}")

            # Track pending CFP
            pending = self.agent.get("pending_cfps") or {}
            pending[incident_id] = {
                "threat_type": threat_type,
                "offender_jid": offender_jid,
                "alert": alert,
                "proposals": [],
                "status": "waiting",
                "deadline": asyncio.get_event_loop().time() + 2.0,  # 2 second deadline
                "cfp_time": datetime.datetime.now().isoformat()
            }
            self.agent.set("pending_cfps", pending)

            # Send CFP to all response agents
            for resp_jid in response_jids:
                cfp = Message(to=resp_jid)
                cfp.set_metadata("protocol", "cnp-cfp")
                cfp.set_metadata("performative", "CFP")
                cfp.set_metadata("incident_id", incident_id)
                cfp.set_metadata("threat_type", threat_type)
                cfp.set_metadata("severity", "high")
                cfp.set_metadata("offender_jid", offender_jid)
                cfp.body = f"CFP for incident {incident_id}: {threat_type} from {offender_jid}"
                await self.send(cfp)
                _log("MonitoringAgent", str(self.agent.jid), f"Sent CFP to {resp_jid}")

            # Schedule proposal evaluation (will happen automatically in CNP behaviour)
            # After 2.1s, CNP behaviour will check deadline and evaluate

        async def run(self):
            msg = await self.receive(timeout=1)
            if msg:
                # --- INÍCIO DA MODIFICAÇÃO (RUN / THREAT-ALERT) ---
                protocol = msg.get_metadata("protocol")
                if protocol == "threat-alert":
                    _log("MonitoringAgent", str(self.agent.jid), f"Threat alert from router: {msg.body}")
                    try:
                        parts = msg.body.split(":", 1)
                        if len(parts) == 2:
                            header = parts[0]  # "THREAT from X to Y"
                            from_match = header.split("from ")[1].split(" to ")[0] if "from " in header else "unknown"
                            offender_jid = from_match.strip()

                            # --- INÍCIO DA CORREÇÃO DE CLASSIFICAÇÃO ---
                            alert_body = msg.body.lower()
                            # Default é malware, a menos que encontremos palavras de insider_threat
                            threat_type = "malware"

                            # Usamos a lista de low_priority_keywords para reclassificar
                            for kw in self.low_priority_keywords:
                                if kw in alert_body:
                                    threat_type = "insider_threat"
                                    break
                            # --- FIM DA CORREÇÃO ---

                            alert = {
                                "time": datetime.datetime.now().isoformat(),
                                "sender": offender_jid,
                                "body": msg.body,
                                "reasons": ["firewall-detected-threat"]
                            }
                            # Usamos o threat_type corrigido
                            await self.initiate_cnp(offender_jid, threat_type, alert)
                    except Exception as e:
                        _log("MonitoringAgent", str(self.agent.jid), f"Error parsing threat alert: {e}")
                    return
                # --- FIM DA MODIFICAÇÃO (RUN / THREAT-ALERT) ---

                # Check if this is a network copy from router (for monitoring)
                if protocol == "network-copy":
                    _log("MonitoringAgent", str(self.agent.jid),
                         f"[MONITOR] Analyzing network message from router: {msg.sender}")
                    # Process the copied message for threat detection
                    try:
                        await self.process_message(msg)
                    except Exception as e:
                        _log("MonitoringAgent", str(self.agent.jid), f"ERROR processing network-copy: {e}")
                    return

                # handle monitoring of any other message
                try:
                    await self.process_message(msg)
                except Exception as e:
                    _log("MonitoringAgent", str(self.agent.jid), f"ERROR processing message: {e}")

    async def setup(self):
        _log("MonitoringAgent", str(self.jid), "starting...")

        # Initialize resource tracking
        self.set("cpu_usage", 20.0)  # Base monitoring CPU
        self.set("bandwidth_usage", 10.0)  # Base monitoring bandwidth
        self.set("messages_analyzed", 0)  # Message counter

        # Initialize CNP tracking
        self.set("pending_cfps", {})
        self.set("incident_counter", 0)  # Counter for incident IDs

        # Start resource monitoring behaviour
        resource_behav = self.ResourceBehaviour(period=2.0)
        self.add_behaviour(resource_behav)

        # Start monitoring behaviour
        monitor_behav = self.MonitorBehav()
        self.add_behaviour(monitor_behav)

        # Start CNP initiator behaviour if response agents configured
        response_jids = self.get("response_jids") or []
        if response_jids:
            cnp_behav = self.CNPInitiatorBehaviour()
            self.add_behaviour(cnp_behav)
            _log("MonitoringAgent", str(self.jid), f"CNP enabled with {len(response_jids)} response agents")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Monitoring agent JID")
    parser.add_argument("--password", required=False, help="Agent password; if omitted you'll be prompted")
    parser.add_argument("--nodes", default="", help="Comma-separated node JIDs to instruct for blocking (optional)")
    parser.add_argument("--response", default="",
                        help="Comma-separated response agent JIDs for CNP auctions (replaces legacy single response)")
    parser.add_argument("--auto-block", action="store_true",
                        help="If set, send BLOCK_JID commands to nodes on detections")
    parser.add_argument("--window", type=int, default=10, help="Time window in seconds for rate detection")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold count within window to trigger rate alert")
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

    # Configure the monitoring behaviour thresholds if provided
    # (behaviour created in setup; find and adjust)
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