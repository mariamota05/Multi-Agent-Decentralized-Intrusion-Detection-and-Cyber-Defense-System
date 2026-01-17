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
    """Log a message with timestamp, agent type, and JID.

    Args:
        agent_type (str): The type of the agent (e.g., "IncidentResponse").
        jid (str): The JID of the agent instance.
        msg (str): The message content to display.
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class IncidentResponseAgent(Agent):
    """CNP Participant that bids on incident response tasks."""

    class CleanupBehaviour(PeriodicBehaviour):
        async def run(self):
            """Removes completed incidents from the `active_incidents` dictionary after a 5-second cooldown."""
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
            """Updates the agent's simulated CPU and Bandwidth usage based on the number of active mitigation tasks.

            Each active mitigation task adds 15.0% to the CPU load, up to 100%.
            """
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
            """Initializes the CNP participant behavior."""
            _log("IncidentResponse", str(self.agent.jid), "CNP Participant behaviour started")

        def calculate_availability_score(self) -> float:
            """Calculates the agent's availability score for bidding in a CNP auction.

            The score reflects the current CPU usage plus a penalty for each currently
            active incident being mitigated. Lower score wins.

            Returns:
                float: The availability score.
            """
            cpu = float(self.agent.get("cpu_usage") or 20.0)
            incidents = self.agent.get("active_incidents") or {}
            active = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")
            return cpu + active * 10.0

        async def handle_cfp(self, msg: Message):
            """Processes a Call for Proposal (CFP) message from a monitoring agent.

            Checks the agent's current CPU load. If CPU is over 85% (indicating near saturation),
            it sends a REFUSE. Otherwise, it calculates the availability score and sends a PROPOSE.

            Args:
                msg (Message): The incoming CFP message.
            """
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")

            # Check if we have capacity for a new incident (15% CPU each)
            incidents = self.agent.get("active_incidents") or {}
            active_count = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")
            current_cpu = 10.0 + (active_count * 15.0)

            if current_cpu > 85.0:
                # Refuse CFP - no capacity for new incident
                refused_count = self.agent.get("refused_cfps") or 0
                self.agent.set("refused_cfps", refused_count + 1)

                _log("IncidentResponse", str(self.agent.jid),
                     f"REFUSED CFP for incident {incident_id}: CPU={current_cpu:.1f}% ({active_count} active incidents, no capacity)")

                refuse = Message(to=str(msg.sender))
                refuse.set_metadata("protocol", "cnp-refuse")
                refuse.set_metadata("incident_id", incident_id)
                refuse.set_metadata("performative", "REFUSE")
                refuse.body = f"Overloaded: CPU={current_cpu:.1f}%"
                await self.send(refuse)
                return

            score = self.calculate_availability_score()
            _log("IncidentResponse", str(self.agent.jid), f"Received CFP for incident {incident_id}: {threat_type} (CPU={current_cpu:.1f}%)")

            proposal = Message(to=str(msg.sender))
            proposal.set_metadata("protocol", "cnp-propose")
            proposal.set_metadata("incident_id", incident_id)
            proposal.set_metadata("performative", "PROPOSE")
            proposal.set_metadata("availability_score", str(score))
            proposal.body = f"Proposal for incident {incident_id}"
            await self.send(proposal)
            _log("IncidentResponse", str(self.agent.jid), f"Sent proposal for incident {incident_id} with score {score:.2f}")

        async def handle_accept_proposal(self, msg: Message):
            """Processes an ACCEPT_PROPOSAL message, signaling the agent has won the contract.

            The incident is marked as `mitigating` and the mitigation process is launched
            as an asynchronous task to prevent blocking the main message receiving loop.

            Args:
                msg (Message): The incoming ACCEPT_PROPOSAL message.
            """
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            offender_jid = msg.get_metadata("offender_jid")
            victim_jid = msg.get_metadata("victim_jid")
            intensity_str = msg.get_metadata("intensity")
            intensity = int(intensity_str) if intensity_str else 5
            monitor_jid = str(msg.sender)

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

            # Run mitigation asynchronously so we can continue receiving CFPs
            asyncio.create_task(self._execute_mitigation_async(incident_id, threat_type, offender_jid, victim_jid, intensity, monitor_jid))

        async def _execute_mitigation_async(self, incident_id: str, threat_type: str, offender_jid: str, victim_jid: str, intensity: int, monitor_jid: str):
            """Wrapper to execute mitigation and inform the monitor of the result.

            This is run as a separate task to maintain responsiveness to new CFPs.

            Args:
                incident_id (str): The ID of the incident.
                threat_type (str): The classified threat type.
                offender_jid (str): The attacker's JID.
                victim_jid (str): The victim's JID.
                intensity (int): The attacker's intensity level.
                monitor_jid (str): The JID of the monitoring agent that awarded the contract.
            """
            success = await self.execute_mitigation(incident_id, threat_type, offender_jid, victim_jid, intensity)

            incidents = self.agent.get("active_incidents") or {}
            if incident_id in incidents:
                incidents[incident_id]["status"] = "resolved" if success else "failed"
                incidents[incident_id]["end_time"] = datetime.datetime.now().isoformat()
                self.agent.set("active_incidents", incidents)

            inform = Message(to=monitor_jid)
            inform.set_metadata("protocol", "cnp-inform")
            inform.set_metadata("incident_id", incident_id)
            inform.set_metadata("performative", "INFORM")
            inform.set_metadata("status", "success" if success else "failure")
            inform.body = f"Incident {incident_id} {'resolved' if success else 'failed'}"
            await self.send(inform)
            _log("IncidentResponse", str(self.agent.jid), f"Sent INFORM for incident {incident_id}: {'SUCCESS' if success else 'FAILURE'}")

        async def execute_mitigation(self, incident_id: str, threat_type: str, offender_jid: str, victim_jid: str = None, intensity: int =None) -> bool:
            """Executes the specific mitigation steps based on the threat type.

            Mitigation is structured in phases (Investigation, Containment/Mitigation, Eradication/Enforcement),
            with the duration of each phase being dependent on the attacker's `intensity`.

            Args:
                incident_id (str): The ID of the incident.
                threat_type (str): The classified type of the threat.
                offender_jid (str): The JID of the attacker/offender.
                victim_jid (str, optional): The JID of the victim.
                intensity (int, optional): The attacker's intensity (1-10).

            Returns:
                bool: True if mitigation was completed successfully, False otherwise.
            """
            if hasattr(self.agent, "mitigation_history"):
                self.agent.mitigation_history.append(datetime.datetime.now())

            victim_str = str(victim_jid) if victim_jid else "unknown"

            # PHASE 1: Investigation & Analysis (intensity-based)
            # Higher intensity = more sophisticated attack = longer investigation
            investigation_time = 2.0 + (intensity * 0.8) if intensity else 4.0
            _log("IncidentResponse", str(self.agent.jid),
                 f"[INVESTIGATING] {threat_type} (intensity={intensity}) - estimated {investigation_time:.1f}s")
            await asyncio.sleep(investigation_time)

            _log("IncidentResponse", str(self.agent.jid),
                 f"Executing mitigation for {threat_type} from {offender_jid} on victim {victim_str}")
            if "attacker" not in offender_jid:
                _log("IncidentResponse", str(self.agent.jid),
                     f"SAFEGUARD: Ignored mitigation request for internal node {offender_jid}. Not an attacker.")
                return False

            nodes_to_protect = self.agent.get("nodes_to_protect") or []

            if threat_type == "malware" or threat_type == "resource_anomaly":
                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: Malware containment - blocking {offender_jid}")

                # PHASE 2: Containment (intensity-based)
                # Higher intensity = more evasive = takes longer to contain
                containment_time = 1.0 + (intensity * 0.6) if intensity else 2.0
                await asyncio.sleep(containment_time)

                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"BLOCK_JID:{offender_jid}"
                    await self.send(ctrl)

                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: {offender_jid} blocked on all nodes.")

                if victim_str != "unknown" and "attacker" not in victim_str:
                    # PHASE 3: Eradication (intensity-based)
                    eradication_time = 1.0 + (intensity * 0.4) if intensity else 1.5
                    await asyncio.sleep(eradication_time)
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

                # PHASE 2: Mitigation (intensity-based)
                # Higher intensity = larger botnet = harder to rate limit
                mitigation_time = 3.0 + (intensity * 0.8) if intensity else 4.0
                await asyncio.sleep(mitigation_time)

                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"RATE_LIMIT:{offender_jid}:10msg/s"
                    await self.send(ctrl)

                _log("IncidentResponse", str(self.agent.jid), f"MITIGATION: Applied rate limiting to {offender_jid}")

                # PHASE 3: Temporary blocking
                blocking_time = 1.0 + (intensity * 0.3) if intensity else 1.5
                await asyncio.sleep(blocking_time)
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

                # PHASE 2: Analysis (intensity-based)
                # Higher intensity = more sophisticated insider = longer to gather evidence
                analysis_time = 2.0 + (intensity * 0.7) if intensity else 4.0
                await asyncio.sleep(analysis_time)

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

                        # PHASE 3: Enforcement (intensity-based)
                        enforcement_time = 1.0 + (intensity * 0.4) if intensity else 1.5
                        await asyncio.sleep(enforcement_time)

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
            """Main loop for the CNP Participant Behaviour.

            Listens for incoming CNP messages (CFP or ACCEPT_PROPOSAL) and delegates
            handling to the appropriate method. Timeout is 1 second per cycle.
            """
            msg = await self.receive(timeout=1)
            if msg:
                protocol = msg.get_metadata("protocol")
                performative = msg.get_metadata("performative")
                if protocol == "cnp-cfp" and performative == "CFP":
                    await self.handle_cfp(msg)
                elif protocol == "cnp-accept" and performative == "ACCEPT_PROPOSAL":
                    await self.handle_accept_proposal(msg)

    async def setup(self):
        """Sets up the IncidentResponseAgent, initializes state, and adds behaviors.

        Initializes state variables for resource tracking, active incidents, and mitigation history.
        Adds CleanupBehaviour, ResourceBehaviour, and CNPParticipantBehaviour.
        """
        _log("IncidentResponse", str(self.jid), "starting...")
        self.set("cpu_usage", 10.0)
        self.set("bandwidth_usage", 3.0)
        self.set("active_incidents", {})
        self.set("suspended_offenders_log", defaultdict(int))
        self.set("refused_cfps", 0) # Counter for refused CFPs due to overload
        self.mitigation_history = [] # Tracks mitigation start times

        self.add_behaviour(self.CleanupBehaviour(period=3.0))
        self.add_behaviour(self.ResourceBehaviour(period=2.0))
        self.add_behaviour(self.CNPParticipantBehaviour())

async def main():
    """Main entry point for running the IncidentResponseAgent from the command line."""
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