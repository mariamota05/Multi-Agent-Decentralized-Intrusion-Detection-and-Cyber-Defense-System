# ...existing code...
import asyncio
import logging
import spade
from computer import ComputerAgent
from router import RouterAgent
from firewall import FirewallAgent


async def main():
    print("Starting environment with Router, Firewall, and Computer agents")

    router = RouterAgent("router@localhost", "router_password")
    firewall = FirewallAgent("firewall@localhost", "firewall_password")
    computer = ComputerAgent("computer@localhost", "computer_password")

    print("Starting Router and Firewall agents...")
    try:
        # add short timeouts so a failed connection raises instead of hanging forever
        await asyncio.wait_for(router.start(auto_register=True), timeout=10)
        await asyncio.wait_for(firewall.start(auto_register=True), timeout=10)
    except Exception as e:
        print("Error starting router/firewall:", e)
        return

    # short delay to ensure registration with XMPP server
    await asyncio.sleep(1.0)

    print("Starting Computer agent...")
    try:
        await asyncio.wait_for(computer.start(auto_register=True), timeout=10)
    except Exception as e:
        print("Error starting computer:", e)
        await router.stop()
        await firewall.stop()
        return

    print("All agents started. Waiting for computer to finish...")
    await spade.wait_until_finished(computer)

    await router.stop()
    await firewall.stop()
    print("Environment finished")
# ...existing code...

if __name__ == "__main__":
    spade.run(main())