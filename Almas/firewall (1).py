import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message
from spade.template import Template


class FirewallAgent(Agent):
    class FilterAndForward(CyclicBehaviour):
        async def run(self):
            # wait for any "inform" message (e.g., from router)
            msg = await self.receive(timeout=60)
            if not msg:
                return  # loop again

            print("Firewall received from {}: {}".format(msg.sender, msg.body))

            # simple filtering rule: only forward messages that contain "ROUTE_INFO"
            if "ROUTE_INFO" in (msg.body or ""):
                fwd = Message(to="computer@localhost")
                fwd.set_metadata("performative", "inform")
                # preserve content and note original sender
                fwd.body = f"{msg.body} (forwarded by firewall from {msg.sender})"
                await self.send(fwd)
                print("Firewall forwarded message to computer@localhost")
            else:
                print("Firewall blocked message (did not match rule)")

    async def setup(self):
        print("FirewallAgent started")
        beh = self.FilterAndForward()
        template = Template()
        template.set_metadata("performative", "inform")
        self.add_behaviour(beh, template)


async def main():
    firewall = FirewallAgent("firewall@localhost", "firewall_password")
    await firewall.start(auto_register=True)
    print("Firewall started")
    await spade.wait_until_finished(firewall)
    print("Firewall finished")


if __name__ == "__main__":
    spade.run(main())
