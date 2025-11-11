"""Small subnetwork test harness.

This script programmatically starts a simple subnetwork:
 - MonitoringAgent (internal monitor)
 - RouterAgent (with local nodes registered)
 - Two NodeAgents (node1, node2)

It sends one test message from node1 to node2 using the router and waits
briefly for logs to appear before stopping all agents.

Run this from the repository root, and ensure you have a running XMPP server
and the accounts either pre-created or allow in-band registration (auto_register).

Example:
  python new/subnetwork.py --domain localhost --password secret

Notes:
 - Uses existing agent classes in the `new` package: NodeAgent, RouterAgent, MonitoringAgent.
 - This harness only demonstrates message flow; it requires a working XMPP service.
"""

import argparse
import asyncio
import os
import json

import spade

from node import NodeAgent
from router import RouterAgent
from monitoring import MonitoringAgent


async def run_subnetwork(domain: str, password: str, run_seconds: int = 6):
    # JID templates
    router_jid = f"router@{domain}"
    monitor_jid = f"monitor@{domain}"
    node1_jid = f"node1@{domain}"
    node2_jid = f"node2@{domain}"

    # Create agents
    monitor = MonitoringAgent(monitor_jid, password)
    router = RouterAgent(router_jid, password)
    node1 = NodeAgent(node1_jid, password)
    node2 = NodeAgent(node2_jid, password)

    # Configure peers and routing before start
    # Nodes will send to the router with metadata 'dst' set to real destination
    node1.set("peers", [str(router_jid)])
    node2.set("peers", [str(router_jid)])

    # Configure router local nodes and monitors
    router.add_local_node(node1_jid)
    router.add_local_node(node2_jid)
    router.set("monitor_jids", [monitor_jid])
    router.set("internal_monitor_jids", [monitor_jid])

    # Start agents (monitor first)
    await monitor.start(auto_register=True)
    await router.start(auto_register=True)
    await node1.start(auto_register=True)
    await node2.start(auto_register=True)

    print("All agents started. Sending test message from node1 -> node2 via router...")

    # Allow behaviours to initialize
    await asyncio.sleep(1)

    # Simple forwarding test: send a message with a small task in metadata so the
    # receiver schedules an active task and ResourceBehav reports the load.
    task_meta = {"duration": 2.0, "cpu_load": 15.0}
    fw1 = node1.get("firewall")
    if fw1:
        sent = await fw1.send_through_firewall(
            str(router_jid),
            "Hello node2, this is node1",
            metadata={"dst": str(node2_jid), "task": json.dumps(task_meta)},
        )
        print(f"node1->router send_through_firewall returned {sent}")
    else:
        msg = spade.message.Message(to=str(router_jid))
        msg.body = "Hello node2, this is node1"
        msg.set_metadata("dst", str(node2_jid))
        msg.set_metadata("task", json.dumps(task_meta))
        await node1.send(msg)
        print("node1->router sent raw message (no firewall)")

    # Wait to allow routing and monitoring to process
    await asyncio.sleep(run_seconds)

    print("Stopping agents...")
    await node1.stop()
    await node2.stop()
    await router.stop()
    await monitor.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", default="localhost", help="XMPP domain/server (default: localhost)")
    parser.add_argument("--password", required=False, help="Password used for all agents (optional)")
    parser.add_argument("--time", type=int, default=6, help="Seconds to wait after sending test message")
    args = parser.parse_args()

    # Prefer explicit CLI password, then environment variable TEST_AGENT_PASSWORD.
    # Fall back to a harmless default 'password' so the script can run non-interactively
    # in local test environments.
    passwd = args.password or os.environ.get("TEST_AGENT_PASSWORD") or "password"

    try:
        spade.run(run_subnetwork(args.domain, passwd, run_seconds=args.time))
    except KeyboardInterrupt:
        print("Interrupted by user; exiting.")


if __name__ == "__main__":
    main()


