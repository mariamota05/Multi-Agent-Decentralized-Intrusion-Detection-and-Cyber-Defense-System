import asyncio
import random
from spade.agent import Agent
from spade.behaviour import FSMBehaviour, State
from spade.message import Message

# Estados do Atacante
STATE_STEALTH = "STEALTH"
STATE_BRUTE_FORCE = "BRUTE_FORCE"
STATE_WAIT = "WAIT"


class AttackerAgent(Agent):
    class AttackFSM(FSMBehaviour):
        async def on_start(self):
            print(f"[{self.agent.name}] Iniciando FSM de Ataque. Começando com STEALTH.")

    # 1. ESTADO: Stealth (Furtivo)
    class StealthState(State):
        async def run(self):
            print(f"[{self.agent.name}] (Estado: STEALTH) Enviando 1 login falhado...")

            msg = Message(to="detector1@localhost")
            msg.set_metadata("performative", "request")  # Simula um 'request' de login
            msg.body = "login_attempt: fail"
            await self.send(msg)

            await asyncio.sleep(10)  # Espera 10 segundos (lento)

            # Decide se continua furtivo ou se inicia Brute Force
            if random.random() < 0.3:
                self.set_next_state(STATE_BRUTE_FORCE)
            else:
                self.set_next_state(STATE_STEALTH)

    # 2. ESTADO: Brute Force (Ataque Rápido)
    class BruteForceState(State):
        async def run(self):
            print(f"[{self.agent.name}] (Estado: BRUTE_FORCE) Iniciando ataque rápido!")
            for i in range(10):  # Envia 10 logins falhados rapidamente
                print(f"[{self.agent.name}] (Estado: BRUTE_FORCE) Enviando login falhado {i + 1}/10")
                msg = Message(to="detector1@localhost")
                msg.set_metadata("performative", "request")
                msg.body = "login_attempt: fail"
                await self.send(msg)
                await asyncio.sleep(0.5)  # Muito rápido

            print(f"[{self.agent.name}] (Estado: BRUTE_FORCE) Ataque concluído. Aguardando...")
            self.set_next_state(STATE_WAIT)

    # 3. ESTADO: Wait (Aguardar)
    class WaitingState(State):
        async def run(self):
            print(f"[{self.agent.name}] (Estado: WAIT) Aguardando 30s antes do próximo ciclo.")
            await asyncio.sleep(30)
            self.set_next_state(STATE_STEALTH)  # Recomeça

    async def setup(self):
        print(f"AttackerAgent {self.name} iniciado.")

        fsm = self.AttackFSM()
        fsm.add_state(name=STATE_STEALTH, state=self.StealthState(), initial=True)
        fsm.add_state(name=STATE_BRUTE_FORCE, state=self.BruteForceState())
        fsm.add_state(name=STATE_WAIT, state=self.WaitingState())

        fsm.add_transition(source=STATE_STEALTH, dest=STATE_STEALTH)
        fsm.add_transition(source=STATE_STEALTH, dest=STATE_BRUTE_FORCE)
        fsm.add_transition(source=STATE_BRUTE_FORCE, dest=STATE_WAIT)
        fsm.add_transition(source=STATE_WAIT, dest=STATE_STEALTH)

        self.add_behaviour(fsm)