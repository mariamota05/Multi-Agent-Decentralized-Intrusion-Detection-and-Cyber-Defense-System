# router_agent.py

import spade
import asyncio
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message
from spade.template import Template


class RouterAgent(Agent):
    class CommandReceiver(CyclicBehaviour):
        """Ouve por ordens de 'NetworkControl' e as executa."""

        async def run(self):
            print(f"[{self.agent.name}] Ouvindo ordens... Reroteamentos atuais: {self.agent.reroute_list}")

            msg = await self.receive(timeout=60)

            if msg:
                print(f"[{self.agent.name}] Ordem recebida de {msg.sender}: {msg.body}")

                if "REROUTE_IP:" in msg.body:
                    ip = msg.body.split(":")[-1]
                    # --- Responsabilidade: Rerotear ---
                    self.agent.reroute_list.add(ip)
                    print(f"[{self.agent.name}] SUCESSO: IP {ip} está sendo reroteado para o Honeypot.")

                    # --- Protocolo: Confirmar Execução ---
                    reply = Message(to=str(msg.sender))
                    reply.set_metadata("performative", "inform")
                    reply.body = f"Ação Concluída: IP {ip} reroteado."
                    await self.send(reply)

                else:
                    print(f"[{self.agent.name}] Ordem não compreendida: {msg.body}")

    async def setup(self):
        print(f"RouterAgent {self.name} iniciado.")
        # --- Permissão: Acesso à Tabela de Roteamento (simulada) ---
        self.reroute_list = set()  # Simula a tabela de roteamento para honeypots

        # Template para ouvir ordens do ResponseAgent
        control_template = Template()
        control_template.set_metadata("performative", "request")
        control_template.set_metadata("protocol", "NetworkControl")

        self.add_behaviour(self.CommandReceiver(), control_template)