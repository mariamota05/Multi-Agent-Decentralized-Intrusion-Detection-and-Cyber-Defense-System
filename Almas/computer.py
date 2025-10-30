import spade
from spade.agent import Agent
from spade.behaviour import OneShotBehaviour
from spade.message import Message
from spade.template import Template


class ComputerAgent(Agent):
    class SendRequest(OneShotBehaviour):
        async def run(self):
            print("SendRequest running")
            msg = Message(to="router@localhost")
            msg.set_metadata("performative", "request")
            msg.body = "REQUEST_INFO: Which route should I use for 10.0.0.0/24?"
            await self.send(msg)
            print("Request sent to router")

    class ReceiveInfo(OneShotBehaviour):
        async def run(self):
            print("ReceiveInfo running")
            msg = await self.receive(timeout=20)  # wait for reply (may be forwarded by firewall)
            if msg:
                print("Received reply from {}: {}".format(msg.sender, msg.body))
            else:
                print("No reply received within 20 seconds")
            await self.agent.stop()

    async def setup(self):
        print("ComputerAgent started")
        # add receiver behaviour filtered for performative "inform"
        recv = self.ReceiveInfo()
        template = Template()
        template.set_metadata("performative", "inform")
        self.add_behaviour(recv, template)

        # add send behaviour
        self.add_behaviour(self.SendRequest())


async def main():
    computer = ComputerAgent("computer@localhost", "computer_password")
    await computer.start(auto_register=True)
    print("Computer started")
    await spade.wait_until_finished(computer)
    print("Computer finished")


if __name__ == "__main__":
    spade.run(main())