"""Scalable network environment for multi-router/multi-node simulation.

This module orchestrates the creation of the network topology, initializes all
SPADE agents (Routers, Nodes, Monitors, Response Agents, and Attackers), and
manages the simulation lifecycle.

Configuration:
    The simulation parameters (topology, number of nodes, attack scenarios) are
    configured via global constants defined in the 'EASY CONFIGURATION' section
    below.

Example:
    Run the simulation with default settings:
    python new/environment.py
"""

import argparse
import asyncio
import csv
import datetime
import os
from typing import List, Dict, Tuple, Optional

import spade
from spade.message import Message
from spade.behaviour import OneShotBehaviour

# Import local agents
from node import NodeAgent
from router import RouterAgent
from monitoring import MonitoringAgent
from response import IncidentResponseAgent

# Import specialized attackers
from attackers.malware_attacker import MalwareAttacker
from attackers.ddos_attacker import DDoSAttacker
from attackers.insider_attacker import InsiderAttacker


# Global variable to track exact attack start time for metrics
REAL_ATTACK_START_TIME: Optional[datetime.datetime] = None


def _log(hint: str, msg: str) -> None:
    """Log helper for environment script with timestamp.

    Args:
        hint (str): The source/category of the log (e.g., 'environment').
        msg (str): The message to display.
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{hint}] {msg}")



# Configuration Section
# Network Topology
NUM_ROUTERS = 5           # Total number of routers in the network
NODES_PER_ROUTER = 3      # Number of nodes attached to each router
ROUTER_TOPOLOGY = "ring"  # Options: "ring", "mesh", "star", "line"

# Security Agents
NUM_RESPONSE_AGENTS = 2  # Number of incident response agents (CNP managers)


# Attacker configuration
# Format: (Type, Targets, Intensity, Duration, Start_Delay)

# STRESS TEST: Mixed attack types to push response agent to 85% CPU limit
# Using MAXIMUM intensity (10) to ensure longest mitigation times and maximum overlap
ATTACKERS = [
    ("ddos", ["router0_node0@localhost"], 10, 30, 0),
    ("stealth_malware", ["router0_node1@localhost"], 10, 30, 0),
    ("insider_threat", ["router1_node0@localhost"], 10, 30, 0),
    ("ddos", ["router1_node1@localhost"], 10, 30, 0),
    ("stealth_malware", ["router2_node0@localhost"], 10, 30, 0),
    ("insider_threat", ["router2_node1@localhost"], 10, 30, 0),
    ("ddos", ["router3_node0@localhost"], 10, 30, 0),
    ("stealth_malware", ["router3_node1@localhost"], 10, 30, 0),
    ("insider_threat", ["router4_node0@localhost"], 10, 30, 0),
    # 9 intensity-10 attacks × 15% CPU = 135% → Response agent MUST refuse several CFPs
    # Each mitigation: ~10s investigation + ~10-12s execution = ~20-22 seconds total
    # With 3s cooldown between CNPs from same attacker, should get 6-7 overlapping incidents
]


#ATTACKERS = [("stealth_malware", ["router1_node0@localhost"], 9, 30, 5), ("ddos", ["router1_node0@localhost"], 9, 30, 5)]
#ATTACKERS = [("insider_threat", ["router1_node0@localhost"], 10, 300, 5)]

# Other examples:
# ATTACKERS = [("stealth_malware", ["router1_node0@localhost"], 9, 30, 5)]
# ATTACKERS = [("ddos", ["router1_node0@localhost"], 8, 30, 5)]
# ATTACKERS = [("stealth_malware", ["router1_node0@localhost"], 9, 30, 5), ("ddos", ["router1_node0@localhost"], 8, 30, 5)]
# ATTACKERS = [("stealth_malware", ["router0_node0@localhost"], 4, 50, 2)]

# Message scheduling configuration
# Format: (Source_Router_ID, Source_Node_ID, Dest_Router_ID, Dest_Node_ID, Body, Delay)
SCHEDULED_MESSAGES = [
    # Before attack starts
    #(0, 0, 1, 0, "PING", 2),
    # --- ATTACK STARTS AT 5s ---
    #(0, 1, 1, 0, "PING", 7),
    # Critical test: Node is under max stress.
    #(2, 0, 1, 0, "PING", 10),
    # Peak Attack
    #(3, 0, 1, 0, "PING", 15),
    # Tests if the node survived and recovered service.
    #(4, 0, 1, 0, "PING", 25),
]

# Deterministic Resource Generation
USE_DETERMINISTIC_RESOURCES = True  # If True, removes randomness from node CPU generation
RESOURCE_SEED_BASE = 1000           # Base seed for deterministic node behavior



def build_router_topology(num_routers: int, topology: str) -> Dict[int, List[int]]:
    """Build router-to-router connectivity graph.
    Generates adjacency lists based on the selected topology type.

    Args:
        num_routers (int): Total number of routers.
        topology (str): Type of topology ("ring", "mesh", "star", "line").

    Returns:
        Dict[int, List[int]]: Dictionary mapping router index to list of neighbor indices.
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
        # Router 0 is the central hub
        for i in range(1, num_routers):
            connections[0].append(i)
            connections[i].append(0)
    elif topology == "line":
        for i in range(num_routers - 1):
            connections[i].append(i + 1)
            connections[i + 1].append(i)
    else:
        raise ValueError(f"Unknown topology: {topology}")

    # Remove duplicates and sort for consistency
    for i in connections:
        connections[i] = sorted(list(set(connections[i])))

    return connections


async def run_environment(domain: str, password: str, run_seconds: int = 300, base_cpu: float = 10.0):
    """Create, configure, and run the full network simulation.

    This is the main entry point for the simulation logic.
    Flow:
    1. Builds the router topology graph.
    2. Instantiates Monitoring and Incident Response agents.
    3. Instantiates Routers and Nodes.
    4. Configures routing tables (using BFS for static path calculation) and neighbors.
    5. Configures Attacker agents.
    6. Starts all agents and scheduled tasks.
    7. Waits for simulation duration.
    8. Collects and prints metrics/reports.
    9. Stops all agents.

    Args:
        domain (str): XMPP domain (e.g., "localhost").
        password (str): XMPP password for all agents.
        run_seconds (int): Duration of the simulation in seconds.
        base_cpu (float): Initial CPU load percentage for nodes.
    """
    _log("environment", f"Building network: {NUM_ROUTERS} routers, {NODES_PER_ROUTER} nodes/router, topology={ROUTER_TOPOLOGY}")

    # Build router connectivity
    router_connections = build_router_topology(NUM_ROUTERS, ROUTER_TOPOLOGY)
    _log("environment", f"Router topology: {router_connections}")

    # Create agents lists
    monitors = []
    routers = []
    nodes = []
    response_agents = []
    attackers = []

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
            node.set("base_cpu", base_cpu)
            # Nodes send to their parent router
            parent_router_jid = f"router{r_idx}@{domain}"
            node.set("router", parent_router_jid)
            node.set("peers", [parent_router_jid])

            if USE_DETERMINISTIC_RESOURCES:
                node.set("resource_seed", node_seed)
                node_seed += 1

            nodes.append((r_idx, n_idx, node_jid, node))

    # Populate subnet_peers for lateral movement (insider threat)
    for r_idx, n_idx, node_jid, node in nodes:
        subnet_peers = []
        for peer_r_idx, peer_n_idx, peer_node_jid, _ in nodes:
            if peer_r_idx == r_idx and peer_node_jid != node_jid:
                subnet_peers.append(peer_node_jid)
        node.set("subnet_peers", subnet_peers)

    # Configure routers: local nodes and inter-router routes
    for r_idx, router_jid, router in routers:
        # Add local nodes
        local_node_count = 0
        for node_r_idx, n_idx, node_jid, _ in nodes:
            if node_r_idx == r_idx:
                router.add_local_node(node_jid)
                local_node_count += 1

        # BFS Routing setup (Static Route Calculation)
        direct_neighbors = router_connections[r_idx]
        from collections import deque
        routes_to_add = {}
        router_neighbors = {}

        for dest_router_idx in range(len(routers)):
            if dest_router_idx == r_idx: continue

            queue = deque([(r_idx, [r_idx])])
            visited = {r_idx}
            found = False

            while queue and not found:
                current_idx, path = queue.popleft()
                if current_idx == dest_router_idx:
                    next_hop_idx = path[1]
                    next_hop_jid = f"router{next_hop_idx}@{domain}"
                    routes_to_add[dest_router_idx] = next_hop_jid
                    found = True
                    break
                for neighbor_idx in router_connections[current_idx]:
                    if neighbor_idx not in visited:
                        visited.add(neighbor_idx)
                        queue.append((neighbor_idx, path + [neighbor_idx]))

        # Apply routes using wildcards for prefixes
        for dest_idx, next_hop_jid in routes_to_add.items():
            prefix = f"router{dest_idx}_*"
            router.add_route(prefix, next_hop_jid)

        # Set initial neighbor metrics for intelligent routing
        for neighbor_idx in direct_neighbors:
            neighbor_router_jid = f"router{neighbor_idx}@{domain}"
            router_neighbors[neighbor_router_jid] = {
                "cpu_usage": 15.0,
                "bandwidth_usage": 8.0
            }

        router.set("router_neighbors", router_neighbors)

        # Attach local monitor
        local_monitor_jid = f"monitor{r_idx}@{domain}"
        router.set("monitor_jids", [local_monitor_jid])
        router.set("internal_monitor_jids", [local_monitor_jid])

    # Configure monitors
    response_jids = [resp_jid for _, resp_jid, _ in response_agents]
    for r_idx, monitor_jid, monitor in monitors:
        monitor.set("response_jids", response_jids)
        all_node_jids = [node_jid for _, _, node_jid, _ in nodes]
        monitor.set("nodes_to_notify", all_node_jids)

    # Configure response agents with protection list (Nodes + Routers)
    all_node_jids = [node_jid for _, _, node_jid, _ in nodes]
    all_router_jids = [router_jid for _, router_jid, _ in routers]
    all_jids_to_protect = all_node_jids + all_router_jids

    for resp_idx, response_jid, response in response_agents:
        response.set("nodes_to_protect", all_jids_to_protect)
        # Give monitor list to response agent for Threat Intel Sharing
        response.set("monitor_jids", [m[1] for m in monitors])

    # Create attacker agents
    for att_idx, (att_type, targets, intensity, duration, delay) in enumerate(ATTACKERS):
        attacker_jid = f"attacker{att_idx}@{domain}"

        if att_type == "stealth_malware":
            attacker = MalwareAttacker(attacker_jid, password)
        elif att_type == "ddos":
            attacker = DDoSAttacker(attacker_jid, password)
        elif att_type == "insider_threat":
            attacker = InsiderAttacker(attacker_jid, password)
        else:
            # Default fallback
            attacker = MalwareAttacker(attacker_jid, password)

        attacker.set("targets", targets)
        attacker.set("intensity", intensity)
        attacker.set("duration", duration)
        attackers.append((att_idx, attacker_jid, attacker, delay))
        _log("environment", f"Configured Attacker {att_idx}: {att_type} -> {targets}")

    # Start agents
    _log("environment", "Starting agents...")
    for r_idx, monitor_jid, monitor in monitors:
        await monitor.start(auto_register=True)
    for resp_idx, response_jid, response in response_agents:
        await response.start(auto_register=True)
    for r_idx, router_jid, router in routers:
        await router.start(auto_register=True)
    for r_idx, n_idx, node_jid, node in nodes:
        await node.start(auto_register=True)

    # Schedule messages
    if SCHEDULED_MESSAGES:
        _log("environment", f"Scheduling {len(SCHEDULED_MESSAGES)} test messages...")
        asyncio.create_task(send_scheduled_messages(nodes, SCHEDULED_MESSAGES, domain))

    # Start attackers
    if ATTACKERS:
        asyncio.create_task(start_attackers_delayed(attackers))

    _log("environment", "All agents started. Network is live.")

    # Run simulation
    await asyncio.sleep(run_seconds)

    # Final status report
    _log("environment", "=" * 80)
    _log("environment", "FINAL NODE STATUS CHECK")
    _log("environment", "=" * 80)

    alive_nodes = []
    dead_nodes = []

    for r_idx, n_idx, node_jid, node in nodes:
        is_dead = node.get("node_dead") or False
        if is_dead:
            dead_nodes.append(node_jid)
            _log("environment", f"[X] {node_jid} - DEAD (crashed from CPU overload)")
        else:
            alive_nodes.append(node_jid)
            cpu = node.get("cpu_usage") or 0.0
            bw = node.get("bandwidth_usage") or 0.0
            is_infected = node.get("is_infected") or False
            is_compromised = node.get("compromised") or False
            if is_infected:
                status = "INFECTED"
            elif is_compromised:
                status = "COMPROMISED"
            else:
                status = "HEALTHY"
            _log("environment", f"[OK] {node_jid} - ALIVE ({status}, CPU={cpu:.1f}% BW={bw:.1f}%)")

    _log("environment", "-" * 80)

    # Metrics and Reporting
    _log("environment", "DETAILED NODE METRICS REPORT")
    _log("environment", "-" * 80)

    total_leakage = 0
    total_overload = 0

    for r_idx, n_idx, node_jid, node in nodes:
        # Extract internal agent metrics
        leakage = node.get("ddos_packets_received") or 0
        overload_ticks = node.get("cpu_overload_ticks") or 0
        pings = node.get("pings_answered") or 0
        is_infected = node.get("is_infected")
        is_compromised = node.get("compromised")
        exfiltration_active = node.get("exfiltration_active")
        exfiltration_bandwidth = node.get("exfiltration_bandwidth") or 0

        # Only show if there is relevant data
        if leakage > 0 or overload_ticks > 0 or pings > 0 or is_infected or is_compromised:
            total_leakage += leakage
            total_overload += overload_ticks

            print(f"\n  NÓ: {node_jid}")
            if is_infected:
                print(f"  [!] STATUS: INFECTED por malware!")
            if is_compromised:
                print(f"  [!] STATUS: COMPROMISED por insider threat (backdoor installed)!")
            if exfiltration_active:
                print(f"  [!] DATA EXFILTRATION ACTIVE: +{exfiltration_bandwidth:.1f}% bandwidth overhead")

            if leakage > 0:
                print(f"  -> Received Malicious Packets not blocked: {leakage}")
                if leakage < 10:
                    print("     (Evaluation: Quick Defense - Most attacks blocked)")
                else:
                    print("     (Evaluation: Slow Defense - Many attacks got through)")
            if overload_ticks > 0:
                print(f"  -> Times CPU reached critical overload: {overload_ticks}")
            else:
                print(f"  -> CPU remained stable throughout the simulation.")

            if pings > 0:
                print(f"  -> Service Availability: Responded to {pings} test pings.")

    last_mitigation = None
    total_refused_cfps = 0
    if response_agents:
        # Agent object is the 3rd element of tuple (idx, jid, agent)
        resp_agent = response_agents[0][2]
        if hasattr(resp_agent, "mitigation_history") and resp_agent.mitigation_history:
            last_mitigation = resp_agent.mitigation_history[0]  # Get first event
        # Get total refused CFPs from response agent
        total_refused_cfps = resp_agent.get("refused_cfps") or 0

    # Find primary victim (router1_node0) to extract peak metrics
    victim_peak_cpu = 0.0
    victim_died = False

    # Default target or attacker's first target
    target_jid = "router1_node0@localhost"
    if ATTACKERS:
        target_jid = ATTACKERS[0][1][0]

    for _, _, node_jid, node in nodes:
        if node_jid == target_jid:
            victim_peak_cpu = node.get("cpu_peak") or 0.0
            victim_died = node.get("node_dead") or False
            break

    stats = {
        'total_leakage': total_leakage,
        'total_overload': total_overload,
        'total_pings': sum(node.get("pings_answered") or 0 for _, _, _, node in nodes),
        'nodes_alive': len(alive_nodes),
        'total_nodes': len(nodes),
        'attack_start': REAL_ATTACK_START_TIME,
        'mitigation_time': last_mitigation,
        'victim_peak_cpu': victim_peak_cpu,
        'victim_died': victim_died,
        'refused_cfps': total_refused_cfps
    }

    print("\n" + "=" * 80)
    _log("environment", f"MÉTRICAS GLOBAIS:")
    _log("environment", f"Total de Ataques não mitigados imediatamente: {total_leakage}")
    _log("environment", f"Total de Ciclos de Saturação de Rede: {total_overload}")
    _log("environment", f"Nós Operacionais: {len(alive_nodes)}/{len(nodes)}")
    _log("environment", f"Total de Pings Respondidos: {stats['total_pings']}")
    _log("environment", f"CFPs Recusados (Response Agent Overloaded): {total_refused_cfps}")
    if REAL_ATTACK_START_TIME:
        _log("environment", f"Início Real do Ataque: {REAL_ATTACK_START_TIME.strftime('%H:%M:%S')}")
    if last_mitigation:
        _log("environment", f"Mitigação Real Efetiva: {last_mitigation.strftime('%H:%M:%S')}")
    _log("environment", "=" * 80)

    # Uncomment to save CSV metrics
    # save_metrics_to_csv("simulation_metrics.csv", ATTACKERS, stats, base_cpu)

    # Save a lightweight CSV just for response-agent metrics (keeps original function unchanged)
    try:
        # number of response agents and total refused CFPs
        num_resp = len(response_agents)
        refused = stats.get('refused_cfps', 0)
        save_response_metrics_csv("response_metrics.csv", num_resp, refused, ATTACKERS)
    except Exception as e:
        _log("environment", f"Failed to save response metrics CSV: {e}")

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
    """Start attacker agents with individual start delays.

    Also records the global `REAL_ATTACK_START_TIME` when the first attacker launches.

    Args:
        attackers (List[Tuple]): List of (index, jid, agent_instance, delay_seconds).
    """
    global REAL_ATTACK_START_TIME
    for att_idx, attacker_jid, attacker, delay in attackers:
        if delay > 0:
            _log("environment", f"Waiting {delay}s before starting attacker {att_idx}...")
            await asyncio.sleep(delay)

        # Mark real attack start time
        if REAL_ATTACK_START_TIME is None:
            REAL_ATTACK_START_TIME = datetime.datetime.now()

        await attacker.start(auto_register=True)
        att_type = type(attacker).__name__.replace("Attacker", "")
        _log("environment", f"Attacker {att_idx} started: {att_type} attack")


async def send_scheduled_messages(
    nodes: List[Tuple[int, int, str, object]],
    messages: List[Tuple[int, int, int, int, str, int]],
    domain: str
):
    """Send a sequence of test messages defined in configuration.

    Used to validate service availability during attacks.

    Args:
        nodes (List): List of existing node tuples.
        messages (List): List of message definitions (src_r, src_n, dst_r, dst_n, body, delay).
        domain (str): XMPP domain.
    """
    async def send_single_message(from_r, from_n, to_r, to_n, msg_body, delay):
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
            return

        destination = f"router{to_r}_node{to_n}@{domain}"

        class SendMessageBehaviour(OneShotBehaviour):
            """One-shot behaviour to send a single scheduled message."""
            async def run(self):
                msg = Message(to=sender_router)
                msg.set_metadata("dst", destination)
                msg.body = msg_body
                await self.send(msg)

        sender.add_behaviour(SendMessageBehaviour())
        _log("environment", f"[SCHED] Message sent: router{from_r}_node{from_n} -> {destination}: {msg_body}")

    tasks = [
        send_single_message(from_r, from_n, to_r, to_n, msg_body, delay)
        for from_r, from_n, to_r, to_n, msg_body, delay in messages
    ]
    await asyncio.gather(*tasks)


def save_metrics_to_csv(filename: str, attack_config: List, network_stats: Dict, base_cpu: float):
    """Save simulation performance metrics to a CSV file.

    Maps the raw internal stats to the specific metrics required by the
    assignment (Detection Rate, Response Time, Resilience, etc.).

    Args:
        filename (str): Path to output CSV file.
        attack_config (List): Configuration of the attack used in this run.
        network_stats (Dict): Dictionary containing collected statistics (leakage, overload, etc.).
        base_cpu (float): The base CPU load configured for this run.
    """
    file_exists = os.path.isfile(filename)

    # Headers mapped to assignment requirements
    headers = [
        'Timestamp',
        'Scenario_Attack',
        'Scenario_Intensity',
        'Metric1_Detection_Rate',      # True Positives
        'Metric2a_False_Positives',    # False Alarms
        'Metric2b_False_Negatives',    # Leakage (packets that got through)
        'Metric3_Response_Time',       # Real time (s)
        'Metric4_Network_Resilience',  # % Uptime
        'Metric4_Service_Availability',# % Pings answered
        'Metric5_Collab_Efficiency',   # Qualitative assessment
        'Metric6_Victim_Peak_CPU',     # Max stress value
        'Metric7_Victim_Crashed',      # Boolean (YES/NO)
        'Raw_Overload_Cycles',         # Raw CPU data
        'Raw_Leakage_Count',           # Raw msg count
        'Scenario_Base_CPU'
    ]

    with open(filename, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()

        # Scenario Data
        if attack_config and len(attack_config) > 0:
            att_type = attack_config[0][0]
            intensity = attack_config[0][2]
        else:
            att_type = "None"
            intensity = 0

        # Raw Statistics
        leakage = network_stats.get('total_leakage', 0)
        overload = network_stats.get('total_overload', 0)
        pings = network_stats.get('total_pings', 0)
        alive = network_stats.get('nodes_alive', 0)
        total_nodes = network_stats.get('total_nodes', 1)

        # METRIC CALCULATION (Business Logic)

        # Detection Rate (True Positives)
        # If mitigation occurred (leakage < 100), detection was successful.
        det_rate = "100%" if leakage < 100 else "0%"

        # False Positives (Conservative assumption)
        fp_rate = "0%"

        # False Negatives (Leakage Rate)
        # Estimate % of attack messages that bypassed defense.
        # Formula: (Leakage / Estimated Total Attack Msgs) * 100
        estimated_attack_msgs = max(1, intensity * 10 * 3 if att_type == 'ddos' else 10)
        fn_rate_val = (leakage / estimated_attack_msgs) * 100
        fn_rate = f"{leakage} msgs ({fn_rate_val:.1f}%)"

        # Response Time (Calculated via Timestamps)
        resp_time_str = "N/A"
        mitigation_ts = network_stats.get('mitigation_time')
        attack_ts = network_stats.get('attack_start')

        if mitigation_ts and attack_ts:
            delta = (mitigation_ts - attack_ts).total_seconds()
            if delta < 0: delta = 0.001
            resp_time_str = f"{delta:.3f}s"
        else:
            # Fallback estimation based on leakage
            if leakage < 5:
                resp_time_str = "< 0.5s (Est)"
            elif leakage < 15:
                resp_time_str = "~ 1.0s (Est)"
            else:
                resp_time_str = "> 3.0s (Slow)"

        # Network Resilience (Uptime)
        uptime_val = (alive / total_nodes) * 100
        uptime = f"{uptime_val:.1f}%"

        # Efficiency of Decentralized Collaboration
        if alive == total_nodes and overload < 5:
            efficiency = "High (Optimal Protection)"
        elif alive == total_nodes:
            efficiency = "Medium (Service Degraded)"
        else:
            efficiency = "Low (System Crash)"

        # Extra metrics
        victim_peak = network_stats.get('victim_peak_cpu', 0.0)
        victim_died = network_stats.get('victim_died', False)

        row = {
            'Timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'Scenario_Attack': att_type,
            'Scenario_Intensity': intensity,
            'Metric1_Detection_Rate': det_rate,
            'Metric2a_False_Positives': fp_rate,
            'Metric2b_False_Negatives': fn_rate,
            'Metric3_Response_Time': resp_time_str,
            'Metric4_Network_Resilience': uptime,
            'Metric4_Service_Availability': f"{pings} Pings OK",
            'Metric5_Collab_Efficiency': efficiency,
            'Metric6_Victim_Peak_CPU': f"{victim_peak:.1f}%",
            'Metric7_Victim_Crashed': "YES" if victim_died else "NO",
            'Raw_Overload_Cycles': overload,
            'Raw_Leakage_Count': leakage,
            'Scenario_Base_CPU': base_cpu
        }
        writer.writerow(row)
        print(f"\n[METRICS] Data saved to {filename}")


def save_response_metrics_csv(filename: str, num_response_agents: int, refused_cfps: int, attack_config: List):
    """Append a small CSV row containing response-agent-specific metrics.

    This function is intentionally small and separated from `save_metrics_to_csv`
    so it does not change existing behavior or column layout.

    Args:
        filename (str): Path to output CSV file.
        num_response_agents (int): The number of IncidentResponseAgents configured.
        refused_cfps (int): The count of Call for Proposals (CFPs) refused by response agents due to overload.
        attack_config (List): The configuration of the attacks for the current run.
    """
    # Ensure relative paths go to the same folder as this module (the `new/` folder)
    if not os.path.isabs(filename):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.join(base_dir, filename)

    file_exists = os.path.isfile(filename)

    # Only store the two fields requested: number of response agents and refused CFPs
    headers = [
        'Num_Response_Agents',
        'Refused_CFPs'
    ]

    with open(filename, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()

        row = {
            'Num_Response_Agents': num_response_agents,
            'Refused_CFPs': refused_cfps
        }
        writer.writerow(row)
        print(f"\n[METRICS] Response metrics (Num_Response_Agents, Refused_CFPs) saved to {filename}")


def main():
    """Parse arguments and run the main event loop for the simulation."""
    parser = argparse.ArgumentParser(description="Run the multi-agent network simulation.")
    parser.add_argument("--domain", default="localhost", help="XMPP domain (default: localhost)")
    parser.add_argument("--password", required=False, help="XMPP password for agents")
    parser.add_argument("--time", type=int, default=40, help="Simulation duration in seconds")
    parser.add_argument("--base-cpu", type=float, default=10.0,
                        help="Initial CPU load for nodes")
    args = parser.parse_args()

    passwd = args.password or os.environ.get("TEST_AGENT_PASSWORD") or "password"

    try:
        spade.run(run_environment(args.domain, passwd, run_seconds=args.time, base_cpu=args.base_cpu))
    except KeyboardInterrupt:
        _log("environment", "Interrupted by user; exiting.")


if __name__ == "__main__":
    main()