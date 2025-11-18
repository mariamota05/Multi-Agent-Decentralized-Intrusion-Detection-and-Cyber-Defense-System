"""
Incident Response Agent - CNP Participant

Responds to incident alerts from monitoring agents using Contract Net Protocol.
When a monitor detects a threat and sends a CFP (Call for Proposals), response
agents evaluate their current workload and bid to handle the incident.

The response agent with the lowest workload (best proposal) wins and executes
mitigation actions such as:
 - Updating firewall rules
 - Blocking malicious JIDs
 - Alerting administrators
 - Coordinating with other security components
"""

import argparse
import asyncio
import datetime
import getpass
from collections import defaultdict
from typing import Dict, Any, List

import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour, PeriodicBehaviour
from spade.message import Message


def _log(agent_type: str, jid: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class IncidentResponseAgent(Agent):
    """
    CNP Participant that bids on incident response tasks.
    """

    class CleanupBehaviour(PeriodicBehaviour):
        async def run(self):
            incidents = self.agent.get("active_incidents") or {}
            now = datetime.datetime.now()
            to_remove = []

            for inc_id, inc_data in incidents.items():
                if inc_data.get("status") in ["resolved", "failed"]:
                    if "end_time" in inc_data:
                        end_time = datetime.datetime.fromisoformat(inc_data["end_time"])
                        age = (now - end_time).total_seconds()
                        if age >= 5.0:
                            to_remove.append(inc_id)

            if to_remove:
                for inc_id in to_remove:
                    del incidents[inc_id]
                self.agent.set("active_incidents", incidents)
                _log("IncidentResponse", str(self.agent.jid),
                     f"Cleaned up {len(to_remove)} completed incidents")

    class ResourceBehaviour(PeriodicBehaviour):
        async def run(self):
            base_cpu = 10.0
            base_bw = 3.0

            incidents = self.agent.get("active_incidents") or {}
            active_count = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")

            incident_cpu = active_count * 15.0
            incident_bw = active_count * 5.0

            cpu_usage = min(100.0, base_cpu + incident_cpu)
            bw_usage = min(100.0, base_bw + incident_bw)

            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bw_usage)

            if active_count > 0:
                _log("IncidentResponse", str(self.agent.jid),
                     f"Resources: cpu={cpu_usage:.1f}% bw={bw_usage:.1f}% active_incidents={active_count}")

    class CNPParticipantBehaviour(CyclicBehaviour):
        async def on_start(self):
            _log("IncidentResponse", str(self.agent.jid), "CNP Participant behaviour started")

        def calculate_availability_score(self) -> float:
            cpu = float(self.agent.get("cpu_usage") or 20.0)
            bw = float(self.agent.get("bandwidth_usage") or 10.0)
            incidents = self.agent.get("active_incidents") or {}
            active = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")

            score = (cpu + bw) / 2.0 + active * 10.0
            return score

        async def handle_cfp(self, msg: Message):
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            severity = msg.get_metadata("severity")

            _log("IncidentResponse", str(self.agent.jid),
                 f"Received CFP for incident {incident_id}: {threat_type} (severity={severity})")

            score = self.calculate_availability_score()

            proposal = Message(to=str(msg.sender))
            proposal.set_metadata("protocol", "cnp-propose")
            proposal.set_metadata("incident_id", incident_id)
            proposal.set_metadata("performative", "PROPOSE")
            proposal.set_metadata("availability_score", str(score))
            proposal.body = f"Proposal for incident {incident_id}: availability_score={score:.2f}"

            await self.send(proposal)
            _log("IncidentResponse", str(self.agent.jid),
                 f"Sent proposal for incident {incident_id} with score {score:.2f}")

        async def handle_accept_proposal(self, msg: Message):
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            offender_jid = msg.get_metadata("offender_jid")
            victim_jid = msg.get_metadata("victim_jid") # Extrair vítima

            _log("IncidentResponse", str(self.agent.jid),
                 f"WON contract for incident {incident_id}! Executing mitigation...")

            incidents = self.agent.get("active_incidents") or {}
            incidents[incident_id] = {
                "threat_type": threat_type,
                "offender_jid": offender_jid,
                "victim_jid": victim_jid,
                "start_time": datetime.datetime.now().isoformat(),
                "status": "mitigating"
            }
            self.agent.set("active_incidents", incidents)

            # Execute mitigation
            success = await self.execute_mitigation(incident_id, threat_type, offender_jid, victim_jid)

            incidents[incident_id]["status"] = "resolved" if success else "failed"
            incidents[incident_id]["end_time"] = datetime.datetime.now().isoformat()
            self.agent.set("active_incidents", incidents)

            inform = Message(to=str(msg.sender))
            inform.set_metadata("protocol", "cnp-inform")
            inform.set_metadata("incident_id", incident_id)
            inform.set_metadata("performative", "INFORM")
            inform.set_metadata("status", "success" if success else "failure")
            inform.body = f"Incident {incident_id} {'resolved' if success else 'failed'}"

            await self.send(inform)
            _log("IncidentResponse", str(self.agent.jid),
                 f"Sent INFORM for incident {incident_id}: {'SUCCESS' if success else 'FAILURE'}")

        async def execute_mitigation(self, incident_id: str, threat_type: str, offender_jid: str, victim_jid: str = None) -> bool:
            if hasattr(self.agent, "mitigation_history"):
                self.agent.mitigation_history.append(datetime.datetime.now())
            # ---------------------------------------------------------

            _log("IncidentResponse", str(self.agent.jid),
                 f"Executing mitigation for {threat_type} from {offender_jid}")

            nodes_to_protect = self.agent.get("nodes_to_protect") or []

            if threat_type == "malware" or threat_type == "resource_anomaly":
                # STRATEGY: Aggressive containment
                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGATION: Malware/Anomaly containment - blocking {offender_jid}")

                await asyncio.sleep(0.3)

                # 1. Block attacker immediately on all nodes
                blocked_count = 0
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"BLOCK_JID:{offender_jid}"
                    await self.send(ctrl)
                    blocked_count += 1

                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGATION: {offender_jid} permanently blocked on {blocked_count} nodes")

                # 2. Cure malware infections (HARD RESET) - if we know who is infected
                # For 'resource_anomaly', the offender IS the infected node.
                target_to_clean = offender_jid if threat_type == "resource_anomaly" else victim_jid

                if target_to_clean:
                    await asyncio.sleep(0.2)
                    cure = Message(to=target_to_clean)
                    cure.set_metadata("protocol", "malware-cure")
                    cure.set_metadata("dst", target_to_clean)
                    cure.body = "CURE_INFECTION"
                    await self.send(cure)
                    _log("IncidentResponse", str(self.agent.jid),
                         f"MITIGATION: HARD RESET sent to {target_to_clean}")

                # 3. Quarantine advisory
                for node_jid in nodes_to_protect:
                    advisory = Message(to=node_jid)
                    advisory.set_metadata("protocol", "firewall-control")
                    advisory.body = f"QUARANTINE_ADVISORY:incident_{incident_id}"
                    await self.send(advisory)

                return True

            elif threat_type == "ddos":
                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGATION: DDoS defense - rate limiting {offender_jid}")

                await asyncio.sleep(0.5)

                # 1. Apply rate limiting first
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"RATE_LIMIT:{offender_jid}:10msg/s"
                    await self.send(ctrl)

                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGATION: Applied rate limiting (10msg/s) to {offender_jid}")

                # 2. Temporary block
                await asyncio.sleep(0.2)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"TEMP_BLOCK:{offender_jid}:15s"
                    await self.send(ctrl)

                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGATION: Temporary block (15s) applied to {offender_jid}")

                return True

            elif threat_type == "insider_threat":
                # STRATEGY: 1st offense = Local suspend. 2nd offense = Global block.

                # Verificar reputação
                offender_log = self.agent.get("suspended_offenders_log")
                offense_count = offender_log[offender_jid] + 1
                offender_log[offender_jid] = offense_count
                self.agent.set("suspended_offenders_log", offender_log)

                if offense_count > 1:
                    # 2ª OFENSA: Bloqueio Global
                    _log("IncidentResponse", str(self.agent.jid),
                         f"MITIGAÇÃO [ESCALADA]: 2ª ofensa de {offender_jid}. A aplicar bloqueio global.")

                    for node_jid in nodes_to_protect:
                        ctrl = Message(to=node_jid)
                        ctrl.set_metadata("protocol", "firewall-control")
                        ctrl.body = f"BLOCK_JID:{offender_jid}"
                        await self.send(ctrl)

                    return True

                # 1ª OFENSA: Suspensão local
                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGAÇÃO [1ª OFENSA]: Insider threat - suspendendo {offender_jid} APENAS no alvo {victim_jid}")

                await asyncio.sleep(0.7)

                if victim_jid:
                    ctrl = Message(to=victim_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"SUSPEND_ACCESS:{offender_jid}"
                    await self.send(ctrl)

                    # Partilhar Threat Intel com monitores
                    monitor_jids = self.agent.get("monitor_jids") or []
                    for mon_jid in monitor_jids:
                        intel_msg = Message(to=mon_jid)
                        intel_msg.set_metadata("protocol", "threat-intel-update")
                        intel_msg.body = f"ADD_TO_WATCHLIST:{offender_jid}"
                        await self.send(intel_msg)
                else:
                     _log("IncidentResponse", str(self.agent.jid),
                          "MITIGAÇÃO FALHOU: No victim_jid provided.")

                # Admin alert
                for node_jid in nodes_to_protect:
                    alert = Message(to=node_jid)
                    alert.set_metadata("protocol", "firewall-control")
                    alert.body = f"ADMIN_ALERT:insider_threat_{incident_id}:{offender_jid}"
                    await self.send(alert)

                return True

            else:
                # Unknown threat
                _log("IncidentResponse", str(self.agent.jid),
                     f"MITIGATION: Unknown threat type '{threat_type}' - applying default block")
                await asyncio.sleep(0.5)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"BLOCK_JID:{offender_jid}"
                    await self.send(ctrl)
                return True

        async def run(self):
            msg = await self.receive(timeout=1)
            if msg:
                protocol = msg.get_metadata("protocol")
                performative = msg.get_metadata("performative")

                if protocol == "cnp-cfp" and performative == "CFP":
                    await self.handle_cfp(msg)
                elif protocol == "cnp-accept" and performative == "ACCEPT_PROPOSAL":
                    await self.handle_accept_proposal(msg)

    async def setup(self):
        _log("IncidentResponse", str(self.jid), "starting...")

        self.set("cpu_usage", 10.0)
        self.set("bandwidth_usage", 3.0)
        self.set("active_incidents", {})
        self.set("suspended_offenders_log", defaultdict(int))
        self.mitigation_history = [] # INICIALIZADO AQUI NO AGENTE

        cleanup_behav = self.CleanupBehaviour(period=3.0)
        self.add_behaviour(cleanup_behav)

        resource_behav = self.ResourceBehaviour(period=2.0)
        self.add_behaviour(resource_behav)

        cnp_behav = self.CNPParticipantBehaviour()
        self.add_behaviour(cnp_behav)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Response agent JID")
    parser.add_argument("--password", required=False, help="Agent password")
    parser.add_argument("--nodes", default="", help="Comma-separated node JIDs")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass()
    nodes = [p.strip() for p in args.nodes.split(',') if p.strip()]

    agent = IncidentResponseAgent(args.jid, passwd)
    agent.set("nodes_to_protect", nodes)

    try:
        await agent.start(auto_register=True)
    except Exception as e:
        _log("IncidentResponse", args.jid, f"Failed to start: {e}")
        return

    _log("IncidentResponse", args.jid, "running. Press Ctrl+C to stop")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        _log("IncidentResponse", args.jid, "Stopping...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    spade.run(main())