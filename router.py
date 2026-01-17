"""Router agent for the simulated network.

RouterAgent attaches a FirewallBehaviour, accepts messages from local nodes or other routers,
sends a copy of each message to configured monitoring agent(s) before forwarding,
and forwards messages according to a simple static routing table.

Message contract (convention): sending agents should send to the router JID and
include the intended destination under metadata key 'dst' (exact destination JID).
"""

import argparse
import asyncio
import datetime
import getpass
from typing import Dict, Set, List, Optional
from collections import deque
import json
from spade.behaviour import CyclicBehaviour, PeriodicBehaviour

import spade
from spade.agent import Agent
from spade.message import Message

from firewall import RouterFirewallBehaviour


def _log(agent_type: str, jid: str, msg: str) -> None:
    """Log formatted message with timestamp.

    Args:
        agent_type (str): Type of agent (e.g., "Router").
        jid (str): Agent JID identifier.
        msg (str): Message to log.
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class RouterAgent(Agent):
    """A simple router agent that forwards messages between nodes/routers.

    Uses BFS-based intelligent routing that considers path length and resource utilization.

    Attributes:
        routing_table (Dict[str, str]): Mapping destination JID or prefix -> next_hop_jid.
        local_nodes (Set[str]): Set of JIDs directly reachable from this router.
        monitor_jids (List[str]): List of monitoring agent JIDs to receive copies.
        router_neighbors (Dict[str, Dict]): Mapping router JID -> {cpu_usage, bandwidth_usage}.
        cpu_usage (float): Current CPU usage percentage.
        bandwidth_usage (float): Current bandwidth usage percentage.
        messages_routed (int): Counter for messages processed.
        firewall (RouterFirewallBehaviour): The attached firewall behaviour instance.
    """

    def find_best_path_bfs(self, destination: str) -> Optional[str]:
        """Find the best path using Breadth-First Search (BFS) considering router resources.

        This method attempts to find a route with the lowest calculated cost, where cost
        is a combination of hop count and the current resource utilization of the next
        hop router in the path. 
        Args:
            destination (str): Target node JID (e.g., "router3_node0@localhost").

        Returns:
            Optional[str]: Next hop JID if path found, None otherwise.

        Note:
            Cost formula: $Cost = (\text{hop\_count} \times 1.0) + (\text{resource\_usage} \times 0.5)$
            where $\text{resource\_usage} = (\text{CPU} + \text{Bandwidth}) / 200$ (normalized 0-1).
        """
        router_neighbors = self.get("router_neighbors") or {}

        # Extract destination router prefix (e.g., "router3" from "router3_node0@localhost")
        dest_parts = destination.split("@")[0].split("_")
        if len(dest_parts) >= 2:
            dest_router_prefix = dest_parts[0]  # e.g., "router3"
        else:
            # Can't determine destination router, fall back to simple routing
            return None

        # BFS to find all paths to destination router
        queue = deque([(str(self.jid), [str(self.jid)], 0.0)])  # (current_router, path, cost)
        visited = {str(self.jid)}
        best_path = None
        best_cost = float('inf')

        while queue:
            current, path, cost = queue.popleft()

            # Extract current router prefix
            current_prefix = current.split("@")[0]

            # Check if we reached destination router
            if current_prefix == dest_router_prefix or (len(path) > 1 and path[-1].split("@")[0] == dest_router_prefix):
                if cost < best_cost:
                    best_cost = cost
                    best_path = path
                continue

            # Check all neighbors of current router
            if current == str(self.jid):
                # For the starting router, use router_neighbors
                for next_hop_jid in router_neighbors.keys():
                    if next_hop_jid in visited:
                        continue

                    # Calculate resource cost for next_hop
                    cpu = router_neighbors[next_hop_jid].get("cpu_usage", 15.0)
                    bw = router_neighbors[next_hop_jid].get("bandwidth_usage", 8.0)
                    resource_cost = (cpu + bw) / 200.0  # Normalize to 0-1

                    # Total cost = hop count + resource weight
                    hop_cost = 1.0
                    total_cost = cost + hop_cost + (resource_cost * 0.5)

                    new_path = path + [next_hop_jid]
                    visited.add(next_hop_jid)
                    queue.append((next_hop_jid, new_path, total_cost))

        # Return first hop if path found
        if best_path and len(best_path) > 1:
            first_hop = best_path[1]
            # Log the BFS routing decision
            path_str = " -> ".join([p.split("@")[0] for p in best_path])
            _log("Router", str(self.jid), f"[BFS] Route to {destination.split('@')[0]}: {path_str} (cost: {best_cost:.2f})")
            return first_hop
        return None

    class ResourceBehaviour(PeriodicBehaviour):
        """Periodically update router resource metrics based on routing activity.

        Updates CPU and bandwidth usage every 2 seconds based on base load and
        recent message routing activity.
        """

        async def run(self):
            """Calculate and update router resource metrics.

            Metrics Calculated:
                - **CPU usage**: Base (15.0%) + routing load ($\text{messages\_routed} \times 2.0\%$).
                - **Bandwidth usage**: Base (8.0%) + routing load ($\text{messages\_routed} \times 1.5\%$).

            The load calculation reflects the overhead of processing and forwarding packets.

            Side Effects:
                Updates 'cpu_usage' and 'bandwidth_usage' in agent storage.
                Resets 'messages_routed' to 0 for the next period measurement.
            """
            # Get current message count
            messages_routed = self.agent.get("messages_routed") or 0

            # Base load for router operation
            base_cpu = 15.0
            base_bw = 8.0

            # Additional load based on routing activity (messages processed in last period)
            routing_cpu = messages_routed * 2.0
            routing_bw = messages_routed * 1.5

            # Calculate total usage (capped at 100%)
            cpu_usage = min(100.0, base_cpu + routing_cpu)
            bandwidth_usage = min(100.0, base_bw + routing_bw)

            # Update agent state
            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", bandwidth_usage)

            # Log resource usage if there was routing activity
            if messages_routed > 0:
                _log("Router", str(self.agent.jid),
                    f"Resource update: cpu={cpu_usage:.1f}% bw={bandwidth_usage:.1f}% msgs_routed={messages_routed}")

            # Reset message counter for next period
            self.agent.set("messages_routed", 0)

    class RouterBehav(CyclicBehaviour):
        """Main routing behaviour handling message reception and forwarding.

        This behaviour listens for incoming messages, applies firewall rules,
        handles special protocols (node-death, threat-alert), forwards copies
        to monitors, and routes packets to their destination.
        """

        async def run(self):
            """Process incoming messages and route to destination.

            Flow:
                1. **Receive**: Wait for a message (timeout=1s).
                2. **Metrics**: Increment `messages_routed` counter.
                3. **Special Handling**: Process `node-death` (removes local node) and `threat-alert` (forwards to monitors).
                4. **Firewall Inbound**: Check message against inbound firewall rules.
                5. **Destination Check**: Determine `dst` and check `TTL`.
                6. **Monitoring**: Send a copy of the message (with preserved metadata) to configured monitoring agents.
                7. **Forwarding Decision**:
                    * **Local**: Deliver directly if `dst` is in `local_nodes`.
                    * **Intelligent Routing**: Use **BFS** (`find_best_path_bfs`) to find the lowest cost next hop.
                    * **Fallback**: Use static `routing_table` if BFS fails.
                8. **Firewall Outbound**: Check message against outbound firewall rules before sending to the next hop.
            """
            msg = await self.receive(timeout=1)
            if not msg:
                return

            # 1. Increment messages_routed counter for resource tracking
            self.agent.set("messages_routed", (self.agent.get("messages_routed") or 0) + 1)

            _log("Router", str(self.agent.jid), f"received msg from {msg.sender}")

            # Check protocol for special messages
            protocol = msg.get_metadata("protocol")

            # 2. Handle node death notifications
            if protocol == "node-death":
                dead_node = str(msg.sender)
                _log("Router", str(self.agent.jid), f"Node {dead_node} reported death: {msg.body}")
                # Remove from local_nodes to stop routing to it
                local = self.agent.get("local_nodes") or set()
                if dead_node in local:
                    local.discard(dead_node)
                    self.agent.set("local_nodes", local)
                    _log("Router", str(self.agent.jid), f"Removed {dead_node} from routing table - no longer forwarding")
                return

            # Check if this is a threat alert from a node firewall
            if protocol == "threat-alert":
                _log("Router", str(self.agent.jid), f"Threat alert received: {msg.body}")

                # Forward to monitors
                monitors = self.agent.get("monitor_jids") or []
                for monitor_jid in monitors:
                    fwd = Message(to=monitor_jid)
                    fwd.set_metadata("protocol", "threat-alert")
                    fwd.body = msg.body

                    # Forward metadata needed for CNP auction
                    if msg.metadata:
                        if "offender" in msg.metadata:
                            fwd.set_metadata("offender", msg.get_metadata("offender"))
                        if "dst" in msg.metadata:
                            fwd.set_metadata("dst", msg.get_metadata("dst"))
                        if "threat_type" in msg.metadata:
                            fwd.set_metadata("threat_type", msg.get_metadata("threat_type"))

                    await self.send(fwd)
                    _log("Router", str(self.agent.jid), f"Forwarded threat alert to {monitor_jid}")
                return

            # Small delay to simulate message reception/processing
            await asyncio.sleep(0.1)

            # 3. Firewall inbound check
            fw = self.agent.get("firewall")
            if fw:
                allowed = await fw.allow_message(msg)
                if not allowed:
                    _log("Router", str(self.agent.jid), f"Firewall blocked inbound message from {msg.sender}")
                    return
                else:
                    sender_jid = str(msg.sender)
                    if "response" not in sender_jid:
                        _log("Router", str(self.agent.jid), f"Firewall allowed message from {sender_jid}")


            dst = None
            parsed = None
            try:
                parsed = json.loads(str(msg.body)) if msg.body else None
            except Exception:
                parsed = None

            # Determine destination for normal forwarding
            if msg.metadata and "dst" in msg.metadata:
                dst = msg.metadata.get("dst")
            else:
                dst = str(msg.to) if msg.to else None

            if not dst:
                _log("Router", str(self.agent.jid), "message missing dst metadata; dropping")
                return

            # Check TTL (Time-To-Live) to prevent routing loops
            ttl = int(msg.metadata.get("ttl", 64)) if msg.metadata else 64
            if ttl <= 0:
                _log("Router", str(self.agent.jid), f"TTL expired for packet to {dst}; dropping")
                return
            ttl -= 1  # Decrement TTL for next hop

            # Determine original sender
            original_sender = msg.get_metadata("original_sender") if msg.metadata else None
            if not original_sender:
                original_sender = str(msg.sender)

            # 4. Send copy to monitoring agents first
            monitors = self.agent.get("monitor_jids") or []
            internal_monitors = self.agent.get("internal_monitor_jids") or []
            local = self.agent.get("local_nodes") or set()
            sender_jid = str(msg.sender) if msg.sender else None
            is_internal = False
            if sender_jid and dst and local:
                is_internal = (sender_jid in local and dst in local)

            target_monitors = internal_monitors if is_internal and internal_monitors else monitors

            for m in target_monitors:
                copy_body = msg.body
                copy_metadata = {
                    "protocol": "network-copy",
                    "original_sender": original_sender,
                    "original_destination": dst
                }

                # Preserve important attack metadata for monitoring
                if msg.metadata:
                    for key in ["attacker_intensity", "task", "spread_intensity"]:
                        if key in msg.metadata:
                            copy_metadata[key] = msg.get_metadata(key)

                if fw:
                    await fw.send_through_firewall(m, copy_body, metadata=copy_metadata)
                else:
                    cm = Message(to=m)
                    cm.body = copy_body
                    for k, v in copy_metadata.items():
                        cm.set_metadata(k, v)
                    await self.send(cm)

            # Small pause
            await asyncio.sleep(0.3)

            # 5. Forwarding decision
            routing: Dict[str, str] = self.agent.get("routing_table") or {}

            if dst in local:
                # Direct delivery to a local node
                out = Message(to=dst)
                out.body = msg.body
                out.set_metadata("via", str(self.agent.jid))
                out.set_metadata("ttl", str(ttl))
                out.set_metadata("original_sender", original_sender)

                if msg.metadata:
                    for key, value in msg.metadata.items():
                        if key not in ["dst", "via", "ttl", "original_sender"]:
                            out.set_metadata(key, value)

                if fw:
                    fw_metadata = {"via": str(self.agent.jid), "ttl": str(ttl),
                                   "original_sender": original_sender}
                    if msg.metadata:
                        for key, value in msg.metadata.items():
                            if key not in ["dst", "via", "ttl", "original_sender"]:
                                fw_metadata[key] = value

                    sent = await fw.send_through_firewall(dst, out.body, metadata=fw_metadata)
                    if sent:
                        _log("Router", str(self.agent.jid), f"Forwarded locally to {dst}")
                    else:
                        _log("Router", str(self.agent.jid), f"Firewall blocked forwarding to local {dst}")
                else:
                    await self.send(out)
                    # Emit packet event for visualization
                    viz = self.agent.get("_visualizer")
                    if viz:
                        viz.add_packet(str(self.agent.jid), dst)
                return

            # Intelligent routing (BFS)
            next_hop = self.agent.find_best_path_bfs(dst)

            # Fallback to simple static routing
            if not next_hop:
                next_hop = routing.get(dst)
                if not next_hop:
                    # Check for wildcard prefix match (e.g., routerX_*)
                    for pat, nh in routing.items():
                        if pat.endswith("*"):
                            # Logic to match routerX_* to routerX_nodeY@domain
                            dst_prefix = dst.split("@")[0].rsplit("_", 1)[0] if "_" in dst.split("@")[0] else dst.split("@")[0]
                            pat_prefix = pat.rstrip("_*")
                            if dst_prefix == pat_prefix:
                                next_hop = nh
                                break

            if not next_hop:
                _log("Router", str(self.agent.jid), f"No route for {dst}; dropping packet")
                return

            # Forward to next hop
            _log("Router", str(self.agent.jid),
                 f"[FWD] Forwarding to {next_hop.split('@')[0]} -> final dest: {dst.split('@')[0]}")
            fwd_body = msg.body

            # Outbound firewall check and send
            if fw:
                sent_ok = await fw.send_through_firewall(next_hop, fwd_body,metadata={"dst": dst, "via": str(self.agent.jid),"ttl": str(ttl), "original_sender": original_sender})
            else:
                fwd = Message(to=next_hop)
                fwd.body = fwd_body
                fwd.set_metadata("dst", dst)
                fwd.set_metadata("via", str(self.agent.jid))
                fwd.set_metadata("ttl", str(ttl))
                fwd.set_metadata("original_sender", original_sender)
                await self.send(fwd)
                sent_ok = True

            if sent_ok:
                _log("Router", str(self.agent.jid), f"Forwarded {dst} via next hop {next_hop}")
            else:
                _log("Router", str(self.agent.jid), f"Firewall prevented forwarding to {next_hop} for dst {dst}")

    async def setup(self):
        """Initialize router agent and attach behaviours.

        Sets up resource tracking, firewall, routing structures, and starts
        the main routing behaviours (`ResourceBehaviour` and `RouterBehav`).
        """
        _log("Router", str(self.jid), "starting...")

        # Initialize resource tracking
        self.set("cpu_usage", 15.0)
        self.set("bandwidth_usage", 8.0)
        self.set("messages_routed", 0)
        self.set("router_neighbors", {})

        # attach a router-specific firewall behaviour and store reference
        fw = RouterFirewallBehaviour()
        self.add_behaviour(fw)
        self.set("firewall", fw)

        self.set("role", "router")

        if not self.get("routing_table"):
            self.set("routing_table", {})
        if not self.get("local_nodes"):
            self.set("local_nodes", set())
        if not self.get("monitor_jids"):
            self.set("monitor_jids", [])
        if not self.get("internal_monitor_jids"):
            self.set("internal_monitor_jids", [])

        # Print current configuration
        rt = self.get("routing_table") or {}
        ln = self.get("local_nodes") or set()
        monitors = self.get("monitor_jids") or []
        internal = self.get("internal_monitor_jids") or []
        _log("Router", str(self.jid), "configuration:")
        print(f"  local_nodes: {sorted(list(ln))}")
        print(f"  routing_table: {rt}")
        print(f"  monitors: {monitors}, internal_monitors: {internal}")

        # Start behaviours
        resource_behav = self.ResourceBehaviour(period=2.0)
        self.add_behaviour(resource_behav)
        self.add_behaviour(self.RouterBehav())

    def add_route(self, dst_pattern: str, next_hop: str):
        """Add static route to routing table.

        Args:
            dst_pattern (str): Destination pattern (supports wildcard * for prefixes).
            next_hop (str): JID of next hop router.
        """
        rt = self.get("routing_table") or {}
        rt[dst_pattern] = next_hop
        self.set("routing_table", rt)

    def add_local_node(self, jid: str):
        """Register a node as directly attached to this router.

        Args:
            jid (str): Node JID to add to local nodes.
        """
        ln = self.get("local_nodes") or set()
        ln.add(jid)
        self.set("local_nodes", ln)
        _log("Router", str(self.jid), f"node {jid} connected; local_nodes now: {sorted(list(ln))}")

    def add_internal_monitor(self, jid: str):
        """Add monitor for intra-subnet traffic.

        This monitor receives copies of messages moving *within* the local subnet
        (local node to local node).

        Args:
            jid (str): Internal monitor JID.
        """
        ims = self.get("internal_monitor_jids") or []
        ims.append(jid)
        self.set("internal_monitor_jids", ims)


async def main():
    """Parse arguments and start router agent.

    This function handles command-line arguments for configuring the router's
    identity, connections, and initial routing table. It then initializes and
    starts the `RouterAgent` using the SPADE framework.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Router agent JID")
    parser.add_argument("--password", required=False, help="Agent password")
    parser.add_argument("--local", default="", help="Comma-separated local node JIDs")
    parser.add_argument("--routes", default="", help="Comma-separated routes dst:next_hop")
    parser.add_argument("--monitors", default="", help="Comma-separated monitoring agent JIDs")
    parser.add_argument("--internal-monitors", default="", help="Comma-separated internal monitoring agent JIDs")
    parser.add_argument("--no-auto-register", dest="auto_register", action="store_false", help="Disable auto_register")
    args = parser.parse_args()

    passwd = args.password or getpass.getpass()
    local_nodes = [p.strip() for p in args.local.split(',') if p.strip()]
    monitors = [p.strip() for p in args.monitors.split(',') if p.strip()]
    internal_monitors = [p.strip() for p in args.internal_monitors.split(',') if p.strip()]

    agent = RouterAgent(args.jid, passwd)
    agent.set("monitor_jids", monitors)
    agent.set("internal_monitor_jids", internal_monitors)

    for r in [x.strip() for x in args.routes.split(',') if x.strip()]:
        if ':' in r:
            dst, nh = r.split(':', 1)
            agent.add_route(dst.strip(), nh.strip())

    for n in local_nodes:
        agent.add_local_node(n)

    try:
        await agent.start(auto_register=args.auto_register)
    except Exception as e:
        _log("Router", args.jid, f"Failed to start: {e}")
        return

    _log("Router", args.jid, "running. Press Ctrl+C to stop")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        _log("Router", args.jid, "Stopping...")
    finally:
        await agent.stop()


if __name__ == "__main__":
    spade.run(main())