"""
Incident Response Agent - CNP Participant

Responds to incident alerts from monitoring agents using Contract Net Protocol.
"""

import argparse
import asyncio
import datetime
import getpass
from collections import defaultdict
from operator import truediv
from typing import Dict, Any, List
import random
import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour, PeriodicBehaviour
from spade.message import Message


def _log(agent_type: str, jid: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class IncidentResponseAgent(Agent):
    """CNP Participant that bids on incident response tasks."""

    class CleanupBehaviour(PeriodicBehaviour):
        async def run(self):
            incidents = self.agent.get("active_incidents") or {}
            now = datetime.datetime.now()
            to_remove = []

            for inc_id, inc_data in incidents.items():
                if inc_data.get("status") in ["resolved", "failed"]:
                    if "end_time" in inc_data:
                        end_time = datetime.datetime.fromisoformat(inc_data["end_time"])
                        if (now - end_time).total_seconds() >= 5.0:
                            to_remove.append(inc_id)

            if to_remove:
                for inc_id in to_remove:
                    del incidents[inc_id]
                self.agent.set("active_incidents", incidents)
                _log("IncidentResponse", str(self.agent.jid),
                     f"Cleaned up {len(to_remove)} completed incidents")

    class ResourceBehaviour(PeriodicBehaviour):
        async def run(self):
            incidents = self.agent.get("active_incidents") or {}
            active_count = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")
            base_cpu = 10.0
            incident_cpu = active_count * 15.0
            cpu_usage = min(100.0, base_cpu + incident_cpu)

            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", min(100.0, 3.0 + active_count * 5.0))

            if active_count > 0:
                _log("IncidentResponse", str(self.agent.jid),
                     f"Resources: cpu={cpu_usage:.1f}% active_incidents={active_count}")

    class CNPParticipantBehaviour(CyclicBehaviour):
        async def on_start(self):
            _log("IncidentResponse", str(self.agent.jid), "CNP Participant behaviour started")

        def calculate_availability_score(self) -> float:
            cpu = float(self.agent.get("cpu_usage") or 20.0)
            incidents = self.agent.get("active_incidents") or {}
            active = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")
            return cpu + active * 10.0

        async def handle_cfp(self, msg: Message):
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            score = self.calculate_availability_score()
            _log("IncidentResponse", str(self.agent.jid), f"Received CFP for incident {incident_id}: {threat_type}")

            proposal = Message(to=str(msg.sender))
            proposal.set_metadata("protocol", "cnp-propose")
            proposal.set_metadata("incident_id", incident_id)
            proposal.set_metadata("performative", "PROPOSE")
            proposal.set_metadata("availability_score", str(score))
            proposal.body = f"Proposal for incident {incident_id}"
            await self.send(proposal)
            _log("IncidentResponse", str(self.agent.jid), f"Sent proposal for incident {incident_id} with score {score:.2f}")

        async def handle_accept_proposal(self, msg: Message):
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            offender_jid = msg.get_metadata("offender_jid")
            victim_jid = msg.get_metadata("victim_jid")
            intensity_str = msg.get_metadata("intensity")
            intensity = int(intensity_str) if intensity_str else 5

            _log("IncidentResponse", str(self.agent.jid),
                 f"WON contract for incident {incident_id}! Executing mitigation...")

            incidents = self.agent.get("active_incidents") or {}
            incidents[incident_id] = {
                "threat_type": threat_type,
                "offender_jid": offender_jid,
                "victim_jid": victim_jid,
                "intensity": intensity,
                "start_time": datetime.datetime.now().isoformat(),
                "status": "mitigating"
            }
            self.agent.set("active_incidents", incidents)

            success = await self.execute_mitigation(incident_id, threat_type, offender_jid, victim_jid, intensity)

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
            _log("IncidentResponse", str(self.agent.jid), f"Sent INFORM for incident {incident_id}: {'SUCCESS' if success else 'FAILURE'}")

        async def execute_mitigation(self, incident_id: str, threat_type: str, offender_jid: str, victim_jid: str = None, intensity: int =None) -> bool:
            if hasattr(self.agent, "mitigation_history"):
                self.agent.mitigation_history.append(datetime.datetime.now())

            victim_str = str(victim_jid) if victim_jid else "unknown"

            _log("IncidentResponse", str(self.agent.jid),
                 f"Executing mitigation for {threat_type} from {offender_jid} on victim {victim_str}")
            if "attacker" not in offender_jid:
                _log("IncidentResponse", str(self.agent.jid),
                     f"SAFEGUARD: Ignored mitigation request for internal node {offender_jid}. Not an attacker.")
                return False

            nodes_to_protect = self.agent.get("nodes_to_protect") or []

            if threat_type == "malware" or threat_type == "resource_anomaly":
                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: Malware containment - blocking {offender_jid}")
                await asyncio.sleep(0.3)

                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"BLOCK_JID:{offender_jid}"
                    await self.send(ctrl)

                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: {offender_jid} blocked on all nodes.")

                if victim_str != "unknown" and "attacker" not in victim_str:
                    await asyncio.sleep(0.2)
                    cure = Message(to=victim_str)
                    cure.set_metadata("protocol", "malware-cure")
                    cure.body = "CURE_INFECTION"
                    await self.send(cure)

                for node_jid in nodes_to_protect:
                    advisory = Message(to=node_jid)
                    advisory.set_metadata("protocol", "firewall-control")
                    advisory.body = f"QUARANTINE_ADVISORY:incident_{incident_id}"
                    await self.send(advisory)
                return True

            elif threat_type == "ddos":
                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: DDoS defense - rate limiting {offender_jid}")
                await asyncio.sleep(0.5)

                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"RATE_LIMIT:{offender_jid}:10msg/s"
                    await self.send(ctrl)

                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: Applied rate limiting to {offender_jid}")

                await asyncio.sleep(0.2)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"TEMP_BLOCK:{offender_jid}:15s"
                    await self.send(ctrl)
                return True

            elif "insider_threat" in threat_type:
                mitigation_success_rate = max(40, 95 - (intensity * 5))  # 90% at intensity=1

                mitigate = False
                if victim_str == "unknown":
                     _log("IncidentResponse", str(self.agent.jid), "MITIGAÇÃO (Insider): No target identified yet.")
                     return False

                if "login" in threat_type or "unauthorized" in threat_type:
                    if intensity < 7:
                        mitigate = True
                    else:
                        mitigate = False
                else:
                    if "exfiltration" in threat_type:
                        if intensity < 9:
                            mitigate = True
                        else:
                            mitigate = False
                    if "backdoor" in threat_type or "lateral" in threat_type:
                        if intensity == 9:
                            mitigate = True
                        else:
                            bit = random.randint(0, 1)
                            if bit == 0:
                                mitigate = False
                            else:
                                mitigate = True

                if not mitigate:
                    _log("IncidentResponse", str(self.agent.jid),
                         f"[MITIGATION EVADED] Attacker used techniques to bypass initial suspension ({mitigation_success_rate}% success rate)")
                    # Still send forensic clean, but suspension failed
                    forensic_msg = Message(to=victim_str)
                    forensic_msg.set_metadata("protocol", "incident-response")
                    forensic_msg.body = "FORENSIC_CLEAN:insider_threat"
                    await self.send(forensic_msg)
                    return False  # Mitigation partially failed

                else:
                    if "login" in threat_type or "unauthorized" in threat_type:
                        # 1ª OFENSA -> Suspensão Local
                        _log("IncidentResponse", str(self.agent.jid),
                             f"MITIGATION [1]: Insider threat - suspending {offender_jid} access on victim {victim_str}")

                        # Suspend attacker account
                        ctrl = Message(to=victim_str)
                        ctrl.set_metadata("protocol", "firewall-control")
                        ctrl.body = f"SUSPEND_ACCESS:{offender_jid}"
                        await self.send(ctrl)

                        # Notify attacker that they've been blocked (stops attack progression)
                        block_notice = Message(to=offender_jid)
                        block_notice.body = f"ACCOUNT_SUSPENDED: Your account has been suspended due to suspicious activity"
                        await self.send(block_notice)

                        # Send forensic clean to victim node
                        forensic_msg = Message(to=victim_str)
                        forensic_msg.set_metadata("protocol", "incident-response")
                        forensic_msg.body = "FORENSIC_CLEAN:insider_threat"
                        await self.send(forensic_msg)

                        _log("IncidentResponse", str(self.agent.jid), "Admin alert logged + Forensic clean sent.")
                        return True

                    else:
                        if "exfiltration" in threat_type:
                            _log("IncidentResponse", str(self.agent.jid),
                                 f"MITIGATION [2]: Applying permanent ban.")

                            # Notify attacker of permanent ban
                            ban_notice = Message(to=offender_jid)
                            ban_notice.body = f"ACCOUNT_BANNED: Permanent ban due to repeated security violations"
                            await self.send(ban_notice)

                        if "backdoor" in threat_type or "lateral" in threat_type:
                            _log("IncidentResponse", str(self.agent.jid),
                                 f"MITIGATION [3]:Applying permanent ban.")

                            ban_notice = Message(to=offender_jid)
                            ban_notice.body = f"ACCOUNT_BANNED: Permanent ban enforced due to repeated severe violations"
                            await self.send(ban_notice)

                        # Global block and forensic clean on all nodes
                        for node_jid in nodes_to_protect:
                            # Block attacker globally
                            ctrl = Message(to=node_jid)
                            ctrl.set_metadata("protocol", "firewall-control")
                            ctrl.body = f"BLOCK_JID:{offender_jid}"
                            await self.send(ctrl)

                            # Send forensic clean to remove any backdoors
                            forensic_msg = Message(to=node_jid)
                            forensic_msg.set_metadata("protocol", "incident-response")
                            forensic_msg.body = "FORENSIC_CLEAN:insider_threat"
                            await self.send(forensic_msg)

                        return True

            else:
                return False

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
        self.mitigation_history = []

        self.add_behaviour(self.CleanupBehaviour(period=3.0))
        self.add_behaviour(self.ResourceBehaviour(period=2.0))
        self.add_behaviour(self.CNPParticipantBehaviour())

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