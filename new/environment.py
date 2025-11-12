"""Scalable network environment for multi-router/multi-node simulation.

This module creates a configurable network topology with multiple routers
connected to each other and multiple nodes attached to each router. The topology
supports inter-router routing and can be easily visualized.

Configuration:
  - NUM_ROUTERS: number of routers in the network
  - NODES_PER_ROUTER: number of nodes attached to each router
  - ROUTER_TOPOLOGY: how routers connect ("ring", "mesh", "star", or "line")

Usage:
  python new/environment.py --domain localhost --password secret --time 10

Structure:
  - MonitoringAgent: global network monitor
  - RouterAgents: interconnected routers (router0, router1, ..., routerN)
  - NodeAgents: local nodes per router (router0_node0, router0_node1, ...)

Future extensions:
  - pygame visualization with grid layout
  - dynamic topology reconfiguration
  - attacker/response agents integration
"""

import argparse
import asyncio
import os
import json
import datetime
from typing import List, Dict, Tuple

import spade

from node import NodeAgent
from router import RouterAgent
from monitoring import MonitoringAgent


def _log(hint: str, msg: str) -> None:
    """Uniform log helper for environment script."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{hint}] {msg}")


# ============================================================================
# CONFIGURATION - Adjust these to change network topology
# ============================================================================

NUM_ROUTERS = 3  # Number of routers in the network
NODES_PER_ROUTER = 2  # Number of nodes attached to each router
ROUTER_TOPOLOGY = "ring"  # Options: "ring", "mesh", "star", "line"

# Optional: enable deterministic resource simulation for nodes
USE_DETERMINISTIC_RESOURCES = False
RESOURCE_SEED_BASE = 1000  # Base seed for nodes (incremented per node)

# ============================================================================


def build_router_topology(num_routers: int, topology: str) -> Dict[int, List[int]]:
    """Build router-to-router connectivity graph.
    
    Args:
        num_routers: Number of routers
        topology: Type of topology ("ring", "mesh", "star", "line")
    
    Returns:
        Dict mapping router index -> list of neighbor router indices
    
    Examples:
        ring with 4 routers: 0-1-2-3-0
        mesh with 3 routers: every router connects to every other
        star with 4 routers: router 0 is hub, connects to 1,2,3
        line with 4 routers: 0-1-2-3 (no wrap)
    """
    connections = {i: [] for i in range(num_routers)}
    
    if topology == "ring":
        for i in range(num_routers):
            connections[i].append((i + 1) % num_routers)
            connections[i].append((i - 1) % num_routers)
    elif topology == "mesh":
        for i in range(num_routers):
            for j in range(num_routers):
                if i != j:
                    connections[i].append(j)
    elif topology == "star":
        # Router 0 is the hub
        for i in range(1, num_routers):
            connections[0].append(i)
            connections[i].append(0)
    elif topology == "line":
        for i in range(num_routers - 1):
            connections[i].append(i + 1)
            connections[i + 1].append(i)
    else:
        raise ValueError(f"Unknown topology: {topology}")
    
    # Remove duplicates and sort
    for i in connections:
        connections[i] = sorted(list(set(connections[i])))
    
    return connections


def compute_grid_positions(num_routers: int, nodes_per_router: int) -> Dict[str, Tuple[int, int]]:
    """Compute grid positions for routers and nodes for pygame visualization.
    
    Args:
        num_routers: Number of routers
        nodes_per_router: Number of nodes per router
    
    Returns:
        Dict mapping agent name -> (x, y) grid position
    
    Layout strategy:
        - Routers placed in a horizontal line or circle
        - Nodes clustered around their parent router
    """
    positions = {}
    
    # Simple horizontal layout for routers
    router_spacing = 200
    node_offset = 80
    
    for r_idx in range(num_routers):
        router_name = f"router{r_idx}"
        # Routers on a horizontal line
        router_x = r_idx * router_spacing + 100
        router_y = 300
        positions[router_name] = (router_x, router_y)
        
        # Nodes arranged in a small circle around router
        for n_idx in range(nodes_per_router):
            node_name = f"router{r_idx}_node{n_idx}"
            angle = (n_idx / nodes_per_router) * 2 * 3.14159
            node_x = router_x + int(node_offset * (0.5 + 0.5 * (n_idx % 2)))
            node_y = router_y + int(node_offset * ((n_idx // 2) - 0.5))
            positions[node_name] = (node_x, node_y)
    
    # Monitor at top center
    positions["monitor"] = (num_routers * router_spacing // 2, 50)
    
    return positions


async def run_environment(domain: str, password: str, run_seconds: int = 15):
    """Create and run the full network environment.
    
    Args:
        domain: XMPP domain (e.g., "localhost")
        password: Password for all agents
        run_seconds: How long to run before stopping
    """
    _log("environment", f"Building network: {NUM_ROUTERS} routers, {NODES_PER_ROUTER} nodes/router, topology={ROUTER_TOPOLOGY}")
    
    # Build router connectivity
    router_connections = build_router_topology(NUM_ROUTERS, ROUTER_TOPOLOGY)
    _log("environment", f"Router topology: {router_connections}")
    
    # Compute positions for future visualization
    positions = compute_grid_positions(NUM_ROUTERS, NODES_PER_ROUTER)
    
    # Create agents
    monitor_jid = f"monitor@{domain}"
    monitor = MonitoringAgent(monitor_jid, password)
    
    routers = []
    nodes = []
    
    # Create routers
    for r_idx in range(NUM_ROUTERS):
        router_jid = f"router{r_idx}@{domain}"
        router = RouterAgent(router_jid, password)
        routers.append((r_idx, router_jid, router))
    
    # Create nodes and attach to routers
    node_seed = RESOURCE_SEED_BASE
    for r_idx in range(NUM_ROUTERS):
        for n_idx in range(NODES_PER_ROUTER):
            node_jid = f"router{r_idx}_node{n_idx}@{domain}"
            node = NodeAgent(node_jid, password)
            # Nodes send to their parent router
            parent_router_jid = f"router{r_idx}@{domain}"
            node.set("peers", [parent_router_jid])
            
            # Optional: deterministic resources
            if USE_DETERMINISTIC_RESOURCES:
                node.set("resource_seed", node_seed)
                node_seed += 1
            
            nodes.append((r_idx, n_idx, node_jid, node))
    
    # Configure routers: local nodes and inter-router routes
    for r_idx, router_jid, router in routers:
        # Add local nodes (directly connected)
        local_node_count = 0
        for node_r_idx, n_idx, node_jid, _ in nodes:
            if node_r_idx == r_idx:
                router.add_local_node(node_jid)
                local_node_count += 1
        _log("environment", f"Router {r_idx} configured with {local_node_count} local nodes")
        
        # Add PREFIX routes to neighbor subnets (like real network routing)
        # Instead of knowing individual nodes, router knows: "router1_* goes via router1"
        neighbors = router_connections[r_idx]
        for neighbor_idx in neighbors:
            neighbor_router_jid = f"router{neighbor_idx}@{domain}"
            # Prefix route: any node matching "router<neighbor>_*" goes via that router
            prefix = f"router{neighbor_idx}_*"
            router.add_route(prefix, neighbor_router_jid)
        
        # Set monitor
        router.set("monitor_jids", [monitor_jid])
        router.set("internal_monitor_jids", [monitor_jid])
    
    # Start all agents
    _log("environment", "Starting monitor...")
    await monitor.start(auto_register=True)
    
    _log("environment", f"Starting {NUM_ROUTERS} routers...")
    for r_idx, router_jid, router in routers:
        await router.start(auto_register=True)
    
    _log("environment", f"Starting {len(nodes)} nodes...")
    for r_idx, n_idx, node_jid, node in nodes:
        await node.start(auto_register=True)
        parent_router = f"router{r_idx}@{domain}"
        _log("environment", f"Node {node_jid} connected to {parent_router}")
    
    _log("environment", "All agents started. Network is live.")
    
    # Allow behaviours to initialize
    await asyncio.sleep(2)
    
    # Send multiple test messages to demonstrate different routing scenarios
    _log("environment", "=== Starting Test Message Scenarios ===")
    
    # Test 1: Cross-router message (router0 -> router2)
    if NUM_ROUTERS >= 3 and NODES_PER_ROUTER >= 1:
        _log("environment", "Test 1: Cross-router message (router0_node0 -> router2_node0)")
        sender_node = None
        for r_idx, n_idx, node_jid, node in nodes:
            if r_idx == 0 and n_idx == 0:
                sender_node = node
                break
        
        if sender_node:
            dest_jid = f"router2_node0@{domain}"
            parent_router = f"router0@{domain}"
            task_meta = {"duration": 2.0, "cpu_load": 15.0}
            
            fw = sender_node.get("firewall")
            if fw:
                sent = await fw.send_through_firewall(
                    parent_router,
                    f"[Test 1] Cross-router: Hello from router0_node0!",
                    metadata={"dst": dest_jid, "task": json.dumps(task_meta), "ttl": "64"},
                )
                _log("environment", f"Test 1 sent: {sent}")
    
    await asyncio.sleep(1)
    
    # Test 2: Intra-router message (same subnet)
    if NODES_PER_ROUTER >= 2:
        _log("environment", "Test 2: Intra-router message (router1_node0 -> router1_node1)")
        sender_node = None
        for r_idx, n_idx, node_jid, node in nodes:
            if r_idx == 1 and n_idx == 0:
                sender_node = node
                break
        
        if sender_node:
            dest_jid = f"router1_node1@{domain}"
            parent_router = f"router1@{domain}"
            task_meta = {"duration": 1.0, "cpu_load": 10.0}
            
            fw = sender_node.get("firewall")
            if fw:
                sent = await fw.send_through_firewall(
                    parent_router,
                    f"[Test 2] Intra-router: Hello neighbor!",
                    metadata={"dst": dest_jid, "task": json.dumps(task_meta), "ttl": "64"},
                )
                _log("environment", f"Test 2 sent: {sent}")
    
    await asyncio.sleep(1)
    
    # Test 3: Adjacent router message (router0 -> router1)
    if NUM_ROUTERS >= 2 and NODES_PER_ROUTER >= 1:
        _log("environment", "Test 3: Adjacent router message (router0_node1 -> router1_node0)")
        sender_node = None
        for r_idx, n_idx, node_jid, node in nodes:
            if r_idx == 0 and n_idx == 1:
                sender_node = node
                break
        
        if sender_node:
            dest_jid = f"router1_node0@{domain}"
            parent_router = f"router0@{domain}"
            task_meta = {"duration": 1.5, "cpu_load": 12.0}
            
            fw = sender_node.get("firewall")
            if fw:
                sent = await fw.send_through_firewall(
                    parent_router,
                    f"[Test 3] Adjacent router: Quick message!",
                    metadata={"dst": dest_jid, "task": json.dumps(task_meta), "ttl": "64"},
                )
                _log("environment", f"Test 3 sent: {sent}")
    
    await asyncio.sleep(1)
    
    # Test 4: Low TTL message (should expire if multi-hop)
    if NUM_ROUTERS >= 3 and NODES_PER_ROUTER >= 1:
        _log("environment", "Test 4: Low TTL message (router0_node0 -> router2_node0, TTL=1)")
        sender_node = None
        for r_idx, n_idx, node_jid, node in nodes:
            if r_idx == 0 and n_idx == 0:
                sender_node = node
                break
        
        if sender_node:
            dest_jid = f"router2_node0@{domain}"
            parent_router = f"router0@{domain}"
            
            fw = sender_node.get("firewall")
            if fw:
                sent = await fw.send_through_firewall(
                    parent_router,
                    f"[Test 4] Low TTL: This should expire if not direct route!",
                    metadata={"dst": dest_jid, "ttl": "1"},  # TTL=1, will expire after 1 hop
                )
                _log("environment", f"Test 4 sent: {sent}")
    
    _log("environment", "=== All Test Messages Sent ===")
    
    # Run for specified time
    _log("environment", f"Network running for {run_seconds} seconds...")
    await asyncio.sleep(run_seconds)
    
    # Stop all agents
    _log("environment", "Stopping all agents...")
    for r_idx, n_idx, node_jid, node in nodes:
        await node.stop()
    for r_idx, router_jid, router in routers:
        await router.stop()
    await monitor.stop()
    
    _log("environment", "Environment stopped. Goodbye.")


def main():
    parser = argparse.ArgumentParser(description="Run scalable multi-router network environment")
    parser.add_argument("--domain", default="localhost", help="XMPP domain/server (default: localhost)")
    parser.add_argument("--password", required=False, help="Password used for all agents (optional)")
    parser.add_argument("--time", type=int, default=15, help="Seconds to run the network")
    args = parser.parse_args()
    
    passwd = args.password or os.environ.get("TEST_AGENT_PASSWORD") or "password"
    
    try:
        spade.run(run_environment(args.domain, passwd, run_seconds=args.time))
    except KeyboardInterrupt:
        _log("environment", "Interrupted by user; exiting.")


if __name__ == "__main__":
    main()
