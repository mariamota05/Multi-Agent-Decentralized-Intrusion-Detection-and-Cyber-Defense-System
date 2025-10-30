import spade
from spade.agent import Agent
from spade.behaviour import OneShotBehaviour

class MyAgent(Agent):
    class MyBehav(OneShotBehaviour):
        async def run(self):
            print("Hello World!")

    async def setup(self):
        self.add_behaviour(self.MyBehav())

async def main():
    agent = MyAgent("agent@localhost", "password")
    await agent.start()

if __name__ == "__main__":
    spade.run(main())