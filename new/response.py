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

CNP Protocol:
 - Monitor (Initiator) sends CFP with incident details
 - Response agents (Participants) send proposals with their availability score
 - Monitor awards contract to best bidder
 - Winner executes mitigation and reports results

Resource Tracking:
 - CPU and bandwidth usage updated based on active incidents
 - More incidents = higher CPU/bandwidth = worse (higher) availability score
"""

import argparse
import asyncio
import datetime
import getpass
from typing import Dict, Any

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
    
    Stores:
      - active_incidents: dict of incident_id -> incident details
      - cpu_usage: current CPU usage (updated based on workload)
      - bandwidth_usage: current bandwidth usage (updated based on workload)
      - base_cpu: base CPU usage when idle
      - base_bandwidth: base bandwidth usage when idle
    """

    class CleanupBehaviour(PeriodicBehaviour):
        """
        Removes resolved/failed incidents from active_incidents after a delay.
        This prevents the dict from growing indefinitely.
        """
        
        async def run(self):
            incidents = self.agent.get("active_incidents") or {}
            now = datetime.datetime.now()
            to_remove = []
            
            for inc_id, inc_data in incidents.items():
                # If incident is resolved or failed, check if it's been 5+ seconds
                if inc_data.get("status") in ["resolved", "failed"]:
                    if "end_time" in inc_data:
                        end_time = datetime.datetime.fromisoformat(inc_data["end_time"])
                        age = (now - end_time).total_seconds()
                        if age >= 5.0:  # Keep for 5 seconds for logging/debugging
                            to_remove.append(inc_id)
            
            # Remove old incidents
            if to_remove:
                for inc_id in to_remove:
                    del incidents[inc_id]
                self.agent.set("active_incidents", incidents)
                _log("IncidentResponse", str(self.agent.jid), 
                     f"Cleaned up {len(to_remove)} completed incidents")

    class ResourceBehaviour(PeriodicBehaviour):
        """
        Updates CPU and bandwidth based on active incidents.
        Similar to NodeAgent's ResourceBehav but simpler.
        """
        
        async def run(self):
            # Base resource usage when idle
            base_cpu = 10.0
            base_bw = 3.0
            
            # Get active incidents (only count ones still being mitigated)
            incidents = self.agent.get("active_incidents") or {}
            active_count = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")
            
            # Each active incident adds load
            incident_cpu = active_count * 15.0  # 15% CPU per incident
            incident_bw = active_count * 5.0    # 5% bandwidth per incident
            
            cpu_usage = min(100.0, base_cpu + incident_cpu)
            bw_usage = min(100.0, base_bw + incident_bw)
            
            # Update agent resources
            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bw_usage)
            
            # Log resource state periodically
            if active_count > 0:
                _log("IncidentResponse", str(self.agent.jid), 
                     f"Resources: cpu={cpu_usage:.1f}% bw={bw_usage:.1f}% active_incidents={active_count}")

    class CNPParticipantBehaviour(CyclicBehaviour):
        """
        Handles CNP participant protocol:
        1. Receives CFP (Call for Proposals) from monitors
        2. Evaluates workload and sends PROPOSE
        3. If awarded, executes mitigation (ACCEPT_PROPOSAL -> INFORM)
        """

        async def on_start(self):
            _log("IncidentResponse", str(self.agent.jid), "CNP Participant behaviour started")

        def calculate_availability_score(self) -> float:
            """
            Calculate availability score (lower is better).
            Score = (cpu_usage + bandwidth_usage) / 2 + active_incidents * 10
            """
            cpu = float(self.agent.get("cpu_usage") or 20.0)
            bw = float(self.agent.get("bandwidth_usage") or 10.0)
            incidents = self.agent.get("active_incidents") or {}
            # Only count incidents still being mitigated, not resolved/failed ones
            active = sum(1 for inc in incidents.values() if inc.get("status") == "mitigating")
            
            score = (cpu + bw) / 2.0 + active * 10.0
            return score

        async def handle_cfp(self, msg: Message):
            """Handle Call for Proposals from monitor"""
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            severity = msg.get_metadata("severity")
            
            _log("IncidentResponse", str(self.agent.jid), 
                 f"Received CFP for incident {incident_id}: {threat_type} (severity={severity})")
            
            # Calculate our availability score
            score = self.calculate_availability_score()
            
            # Send proposal back to monitor
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
            """Handle acceptance of our proposal - we won the contract!"""
            incident_id = msg.get_metadata("incident_id")
            threat_type = msg.get_metadata("threat_type")
            offender_jid = msg.get_metadata("offender_jid")
            
            _log("IncidentResponse", str(self.agent.jid), 
                 f"WON contract for incident {incident_id}! Executing mitigation...")
            
            # Store incident as active
            incidents = self.agent.get("active_incidents") or {}
            incidents[incident_id] = {
                "threat_type": threat_type,
                "offender_jid": offender_jid,
                "start_time": datetime.datetime.now().isoformat(),
                "status": "mitigating"
            }
            self.agent.set("active_incidents", incidents)
            
            # Execute mitigation based on threat type
            success = await self.execute_mitigation(incident_id, threat_type, offender_jid)
            
            # Update incident status
            incidents[incident_id]["status"] = "resolved" if success else "failed"
            incidents[incident_id]["end_time"] = datetime.datetime.now().isoformat()
            self.agent.set("active_incidents", incidents)
            
            # Send INFORM back to monitor with results
            inform = Message(to=str(msg.sender))
            inform.set_metadata("protocol", "cnp-inform")
            inform.set_metadata("incident_id", incident_id)
            inform.set_metadata("performative", "INFORM")
            inform.set_metadata("status", "success" if success else "failure")
            inform.body = f"Incident {incident_id} {'resolved' if success else 'failed'}"
            
            await self.send(inform)
            _log("IncidentResponse", str(self.agent.jid), 
                 f"Sent INFORM for incident {incident_id}: {'SUCCESS' if success else 'FAILURE'}")

        async def execute_mitigation(self, incident_id: str, threat_type: str, offender_jid: str) -> bool:
            """
            Execute mitigation actions based on threat type.
            Different strategies for different threats:
            - malware: Immediate block + quarantine infected nodes
            - ddos: Rate limiting + temporary block with monitoring
            - insider_threat: Account suspension + access audit + alert admins
            
            Returns True if successful, False otherwise.
            """
            _log("IncidentResponse", str(self.agent.jid), 
                 f"Executing mitigation for {threat_type} from {offender_jid}")
            
            nodes_to_protect = self.agent.get("nodes_to_protect") or []
            
            if threat_type == "malware":
                # STRATEGY: Aggressive containment - immediate block + quarantine
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Malware containment - blocking {offender_jid} across all nodes")
                
                await asyncio.sleep(0.3)  # Quick response critical
                
                # 1. Block attacker immediately on all nodes
                blocked_count = 0
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"BLOCK_JID:{offender_jid}"
                    await self.send(ctrl)
                    blocked_count += 1
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION COMPLETE: {offender_jid} permanently blocked on {blocked_count} nodes - further attacks will be rejected")
                
                # 2. Send quarantine advisory (informational - nodes could isolate infected systems)
                for node_jid in nodes_to_protect:
                    advisory = Message(to=node_jid)
                    advisory.set_metadata("protocol", "firewall-control")
                    advisory.body = f"QUARANTINE_ADVISORY:malware_incident_{incident_id}"
                    await self.send(advisory)
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Sent quarantine advisory for incident {incident_id}")
                
                return True
                
            elif threat_type == "ddos":
                # STRATEGY: Rate limiting + temporary block with monitoring
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: DDoS defense - rate limiting {offender_jid}")
                
                await asyncio.sleep(0.5)  # Moderate response time
                
                # 1. Apply rate limiting first (less aggressive than full block)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"RATE_LIMIT:{offender_jid}:10msg/s"
                    await self.send(ctrl)
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Applied rate limiting (10msg/s) to {offender_jid}")
                
                # 2. If severe, escalate to temporary block
                await asyncio.sleep(0.2)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"TEMP_BLOCK:{offender_jid}:30s"
                    await self.send(ctrl)
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Temporary block (30s) applied to {offender_jid}")
                
                # 3. Schedule monitoring (informational - could trigger follow-up checks)
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Monitoring {offender_jid} for sustained DDoS activity")
                
                return True
                
            elif threat_type == "insider_threat":
                # STRATEGY: Account suspension + access audit + admin alert
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Insider threat response - suspending {offender_jid}")
                
                await asyncio.sleep(0.7)  # Thorough investigation takes time
                
                # 1. Suspend account access (soft block - could be reversed)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"SUSPEND_ACCESS:{offender_jid}"
                    await self.send(ctrl)
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Suspended access for {offender_jid} on all nodes")
                
                # 2. Trigger access audit (informational - logs what the insider accessed)
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Initiating access audit for {offender_jid}")
                
                # 3. Alert administrators (could escalate to human review)
                for node_jid in nodes_to_protect:
                    alert = Message(to=node_jid)
                    alert.set_metadata("protocol", "firewall-control")
                    alert.body = f"ADMIN_ALERT:insider_threat_{incident_id}:{offender_jid}"
                    await self.send(alert)
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Administrator alerts sent for incident {incident_id}")
                
                # 4. Full block if investigation confirms malicious intent
                await asyncio.sleep(0.3)
                for node_jid in nodes_to_protect:
                    ctrl = Message(to=node_jid)
                    ctrl.set_metadata("protocol", "firewall-control")
                    ctrl.body = f"BLOCK_JID:{offender_jid}"
                    await self.send(ctrl)
                
                _log("IncidentResponse", str(self.agent.jid), 
                     f"MITIGATION: Permanent block applied to {offender_jid} after investigation")
                
                return True
            
            else:
                # Unknown threat type - apply conservative default (block)
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
        
        # Initialize resource tracking
        self.set("cpu_usage", 10.0)  # Base idle CPU
        self.set("bandwidth_usage", 3.0)  # Base idle bandwidth
        self.set("active_incidents", {})
        
        # Start cleanup behaviour (removes old resolved/failed incidents)
        cleanup_behav = self.CleanupBehaviour(period=3.0)
        self.add_behaviour(cleanup_behav)
        
        # Start resource monitoring behaviour
        resource_behav = self.ResourceBehaviour(period=2.0)
        self.add_behaviour(resource_behav)
        
        # Start CNP participant behaviour
        cnp_behav = self.CNPParticipantBehaviour()
        self.add_behaviour(cnp_behav)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Response agent JID")
    parser.add_argument("--password", required=False, help="Agent password; if omitted you'll be prompted")
    parser.add_argument("--nodes", default="", help="Comma-separated node JIDs to protect (send firewall commands)")
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