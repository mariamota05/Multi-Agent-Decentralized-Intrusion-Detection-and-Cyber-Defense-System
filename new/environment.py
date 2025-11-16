"""Scalable network environment for multi-router/multi-node simulation.

This module creates a configurable network topology with multiple routers
connected to each other and multiple nodes attached to each router. The topology
supports inter-router routing.

Configuration:
  Edit the variables below to change network topology, attacks, and messages.

Usage:
  python new/environment.py --domain localhost --password secret --time 30

Structure:
  - MonitoringAgents: one per router for local traffic inspection
  - RouterAgents: interconnected routers (router0, router1, ..., routerN)
  - NodeAgents: local nodes per router (router0_node0, router0_node1, ...)
  - Response Agents: CNP participants for incident response
  - Attacker Agents: Simulates malicious behavior
"""

import argparse
import asyncio
import os
import sys
import json
import datetime
from typing import List, Dict, Tuple, Optional

import spade

from node import NodeAgent
from router import RouterAgent
from monitoring import MonitoringAgent
from response import IncidentResponseAgent

# Import specialized attackers
from attackers.malware_attacker import MalwareAttacker
from attackers.ddos_attacker import DDoSAttacker
from attackers.insider_attacker import InsiderAttacker


def _log(hint: str, msg: str) -> None:
    """Uniform log helper for environment script."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    log_msg = f"[{ts}] [{hint}] {msg}"
    print(log_msg)


# ============================================================================
# EASY CONFIGURATION - Edit these variables before running
# ============================================================================

# Network topology
NUM_ROUTERS = 5  # Number of routers in the network
NODES_PER_ROUTER = 2  # Number of nodes attached to each router
ROUTER_TOPOLOGY = "ring"  # Options: "ring", "mesh", "star", "line"

# Security agents
NUM_RESPONSE_AGENTS = 1  # Number of incident response agents (for CNP)

# ============================================================================
# ATTACKER CONFIGURATION
# ============================================================================

# List of attackers to spawn
# Format: [(type, [target_jids], intensity, duration, delay), ...]
# 
# Attack types: "stealth_malware", "ddos", "insider_threat"
# Intensity: 1-10 (higher = more aggressive)
# Duration: seconds to run the attack
# Delay: seconds to wait before starting attack
#
# Examples:
# Single attacker:
# ATTACKERS = [
#     ("stealth_malware", ["router0_node0@localhost"], 5, 20, 3),
# ]
#
# Multiple attackers:
# ATTACKERS = [
#     ("stealth_malware", ["router0_node0@localhost"], 5, 20, 3),
#     ("ddos", ["router1_node0@localhost"], 8, 15, 5),
#     ("insider_threat", ["router2_node0@localhost"], 6, 18, 7),
# ]
#
# No attackers (test routing only):
# ATTACKERS = []
#
ATTACKERS = [("stealth_malware", ["router0_node0@localhost"], 5, 20, 3)]

# ============================================================================
# MESSAGE TESTING (optional - for testing routing)
# ============================================================================

# Scheduled messages - sends test messages between nodes to verify routing
# Format: [(from_router, from_node, to_router, to_node, message, delay), ...]
# 
# Supported message types:
#   "PING" - Simple connectivity test (node replies with "PONG")
#   "REQUEST: <text>" - Processing request (node replies with "RESPONSE: <text>")
#   Any other text - Just delivered to destination (no reply)
#
# Examples:
# SCHEDULED_MESSAGES = [
#     (0, 0, 1, 1, "PING", 2),                    # Test connectivity after 2 seconds
#     (1, 1, 2, 0, "REQUEST: status", 5),         # Request processing after 5 seconds
#     (0, 1, 2, 1, "Hello from router0", 8),      # Custom message after 8 seconds
# ]
SCHEDULED_MESSAGES = []  # Leave empty for no test messages

# ============================================================================
# RESOURCES (usually don't need to change)
# ============================================================================

USE_DETERMINISTIC_RESOURCES = True  # No randomness
RESOURCE_SEED_BASE = 1000  # Base seed for nodes

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
    
    # Create agents
    monitors = []  # One monitor per router
    routers = []
    nodes = []
    response_agents = []  # CNP participants for incident response
    attackers = []  # Malicious agents
    
    # Create monitors (one per router)
    for r_idx in range(NUM_ROUTERS):
        monitor_jid = f"monitor{r_idx}@{domain}"
        monitor = MonitoringAgent(monitor_jid, password)
        monitors.append((r_idx, monitor_jid, monitor))
    
    # Create response agents (for CNP)
    for resp_idx in range(NUM_RESPONSE_AGENTS):
        response_jid = f"response{resp_idx}@{domain}"
        response = IncidentResponseAgent(response_jid, password)
        response_agents.append((resp_idx, response_jid, response))
        _log("environment", f"Created response agent {resp_idx}: {response_jid}")
    
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
            node.set("router", parent_router_jid)  # Set router for message routing
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
        
        # Compute shortest paths to all other routers using BFS
        # For each destination router, find the next hop on the shortest path
        direct_neighbors = router_connections[r_idx]
        
        # BFS to find shortest path to each router
        from collections import deque
        
        routes_to_add = {}  # destination_router_idx -> next_hop_router_jid
        router_neighbors = {}  # Track direct neighbors for resource-aware routing
        
        for dest_router_idx in range(len(routers)):
            if dest_router_idx == r_idx:
                continue  # Skip self
            
            # BFS from current router to destination router
            queue = deque([(r_idx, [r_idx])])
            visited = {r_idx}
            found = False
            
            while queue and not found:
                current_idx, path = queue.popleft()
                
                if current_idx == dest_router_idx:
                    # Found path! The next hop is path[1]
                    next_hop_idx = path[1]
                    next_hop_jid = f"router{next_hop_idx}@{domain}"
                    routes_to_add[dest_router_idx] = next_hop_jid
                    found = True
                    break
                
                # Explore neighbors
                for neighbor_idx in router_connections[current_idx]:
                    if neighbor_idx not in visited:
                        visited.add(neighbor_idx)
                        queue.append((neighbor_idx, path + [neighbor_idx]))
        
        # Add routes for all destination routers
        for dest_idx, next_hop_jid in routes_to_add.items():
            prefix = f"router{dest_idx}_*"
            router.add_route(prefix, next_hop_jid)
        
        # Track direct neighbor resources for BFS (initially use default values)
        for neighbor_idx in direct_neighbors:
            neighbor_router_jid = f"router{neighbor_idx}@{domain}"
            router_neighbors[neighbor_router_jid] = {
                "cpu_usage": 15.0,  # Base router CPU
                "bandwidth_usage": 8.0  # Base router bandwidth
            }
        
        # Set router_neighbors for BFS path finding
        router.set("router_neighbors", router_neighbors)
        
        # Set local monitor for this router with CNP response agents
        local_monitor_jid = f"monitor{r_idx}@{domain}"
        router.set("monitor_jids", [local_monitor_jid])
        router.set("internal_monitor_jids", [local_monitor_jid])
    
    # Configure monitors with CNP response agents
    response_jids = [resp_jid for _, resp_jid, _ in response_agents]
    for r_idx, monitor_jid, monitor in monitors:
        monitor.set("response_jids", response_jids)
        # Give monitors list of all nodes to protect
        all_node_jids = [node_jid for _, _, node_jid, _ in nodes]
        monitor.set("nodes_to_notify", all_node_jids)
        _log("environment", f"Monitor {r_idx} configured with {len(response_jids)} response agents")
    
    # Configure response agents with nodes they can protect
    all_node_jids = [node_jid for _, _, node_jid, _ in nodes]
    for resp_idx, response_jid, response in response_agents:
        response.set("nodes_to_protect", all_node_jids)
    
    # Create attacker agents from ATTACKERS list
    for att_idx, (att_type, targets, intensity, duration, delay) in enumerate(ATTACKERS):
        attacker_jid = f"attacker{att_idx}@{domain}"
        
        # Select specialized attacker based on type
        if att_type == "stealth_malware":
            attacker = MalwareAttacker(attacker_jid, password)
            _log("environment", f"[MALWARE] Created MALWARE attacker {att_idx}: {attacker_jid}")
        elif att_type == "ddos":
            attacker = DDoSAttacker(attacker_jid, password)
            _log("environment", f"[DDOS] Created DDoS attacker {att_idx}: {attacker_jid}")
        elif att_type == "insider_threat":
            attacker = InsiderAttacker(attacker_jid, password)
            _log("environment", f"[INSIDER] Created INSIDER THREAT attacker {att_idx}: {attacker_jid}")
        else:
            _log("environment", f"[!] Unknown attacker type '{att_type}' - defaulting to malware")
            attacker = MalwareAttacker(attacker_jid, password)
        
        attacker.set("targets", targets)
        attacker.set("intensity", intensity)
        attacker.set("duration", duration)
        attackers.append((att_idx, attacker_jid, attacker, delay))
        _log("environment", f"   Targeting: {targets}")
        _log("environment", f"   Intensity: {intensity}/10, Duration: {duration}s, Delay: {delay}s")
    
    # Start all agents
    _log("environment", f"Starting {NUM_ROUTERS} monitors (one per router)...")
    for r_idx, monitor_jid, monitor in monitors:
        await monitor.start(auto_register=True)
        _log("environment", f"Monitor {r_idx} started for router {r_idx}")
    
    _log("environment", f"Starting {NUM_RESPONSE_AGENTS} response agents...")
    for resp_idx, response_jid, response in response_agents:
        await response.start(auto_register=True)
        _log("environment", f"Response agent {resp_idx} started")
    
    _log("environment", f"Starting {NUM_ROUTERS} routers...")
    for r_idx, router_jid, router in routers:
        await router.start(auto_register=True)
    
    _log("environment", f"Starting {len(nodes)} nodes...")
    for r_idx, n_idx, node_jid, node in nodes:
        await node.start(auto_register=True)
        parent_router = f"router{r_idx}@{domain}"
        _log("environment", f"Node {node_jid} connected to {parent_router}")
    
    # Schedule messages if configured
    if SCHEDULED_MESSAGES:
        _log("environment", f"Scheduling {len(SCHEDULED_MESSAGES)} test messages...")
        asyncio.create_task(send_scheduled_messages(nodes, SCHEDULED_MESSAGES, domain))
    
    # Start attacker agents with staggered delays
    if ATTACKERS:
        asyncio.create_task(start_attackers_delayed(attackers))
    
    _log("environment", "All agents started. Network is live.")
    
    # Run for specified duration
    _log("environment", f"Network running for {run_seconds} seconds...")
    await asyncio.sleep(run_seconds)
    
    # Stop all agents
    _log("environment", "Stopping all agents...")
    if ATTACKERS:
        for att_idx, attacker_jid, attacker, _ in attackers:
            await attacker.stop()
    for r_idx, n_idx, node_jid, node in nodes:
        await node.stop()
    for r_idx, router_jid, router in routers:
        await router.stop()
    for resp_idx, response_jid, response in response_agents:
        await response.stop()
    for r_idx, monitor_jid, monitor in monitors:
        await monitor.stop()
    
    _log("environment", "Environment stopped. Goodbye.")


async def start_attackers_delayed(attackers: List[Tuple[int, str, object, int]]):
    """Start attackers with individual delays.
    
    Args:
        attackers: List of (idx, jid, agent, delay) tuples
    """
    for att_idx, attacker_jid, attacker, delay in attackers:
        if delay > 0:
            _log("environment", f"Waiting {delay}s before starting attacker {att_idx}...")
            await asyncio.sleep(delay)
        await attacker.start(auto_register=True)
        att_type = type(attacker).__name__.replace("Attacker", "")
        _log("environment", f"Attacker {att_idx} started: {att_type} attack")


async def send_scheduled_messages(
    nodes: List[Tuple[int, int, str, object]],
    messages: List[Tuple[int, int, int, int, str, int]],
    domain: str
):
    """Send scheduled test messages.
    
    Args:
        nodes: List of (router_idx, node_idx, jid, agent) tuples
        messages: List of (from_router, from_node, to_router, to_node, message, delay) tuples
        domain: XMPP domain
    """
    from spade.message import Message
    from spade.behaviour import OneShotBehaviour
    
    for from_r, from_n, to_r, to_n, msg_body, delay in messages:
        await asyncio.sleep(delay)
        
        # Find sender node
        sender = None
        sender_router = None
        for r_idx, n_idx, node_jid, node in nodes:
            if r_idx == from_r and n_idx == from_n:
                sender = node
                sender_router = f"router{from_r}@{domain}"
                break
        
        if not sender:
            _log("environment", f"[WARN] Sender router{from_r}_node{from_n} not found")
            continue
        
        # Build final destination JID
        destination = f"router{to_r}_node{to_n}@{domain}"
        
        # Create a one-shot behavior to send the message through router
        class SendMessageBehaviour(OneShotBehaviour):
            async def run(self):
                # Send to router with destination metadata
                msg = Message(to=sender_router)
                msg.set_metadata("dst", destination)
                msg.body = msg_body
                await self.send(msg)
        
        # Add and start the behavior
        sender.add_behaviour(SendMessageBehaviour())
        _log("environment", f"[SCHED] Scheduled message sent: router{from_r}_node{from_n} -> router{to_r}_node{to_n}: {msg_body}")


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
