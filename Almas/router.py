import spade
from spade.agent import Agent
from spade.behaviour import OneShotBehaviour
from spade.message import Message
from spade.template import Template


class RouterAgent(Agent):
    class ReceiveRequest(OneShotBehaviour):
        async def run(self):
            print("ReceiveRequest running")
            msg = await self.receive(timeout=30)  # wait for a request from computer
            if msg:
                print("Received request from {}: {}".format(msg.sender, msg.body))
                # send routing info to firewall for filtering/forwarding to computer
                reply = Message(to="firewall@localhost")
                reply.set_metadata("performative", "inform")
                reply.body = "ROUTE_INFO: next-hop 192.168.1.1 for 10.0.0.0/24"
                await self.send(reply)
                print("Route info sent to firewall")
            else:
                print("No request received within 30 seconds")
            await self.agent.stop()

    async def setup(self):
        print("RouterAgent started")
        recv_behav = self.ReceiveRequest()
        template = Template()
        template.set_metadata("performative", "request")
        self.add_behaviour(recv_behav, template)


async def main():
    router = RouterAgent("router@localhost", "router_password")
    await router.start(auto_register=True)
    print("Router started")
    await spade.wait_until_finished(router)
    print("Router finished")


if __name__ == "__main__":
    spade.run(main())
