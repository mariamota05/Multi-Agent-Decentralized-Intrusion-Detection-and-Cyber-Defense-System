from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message
from spade.template import Template


class FirewallAgent(Agent):
    class CommandReceiver(CyclicBehaviour):
        """Ouve por ordens de 'NetworkControl' e as executa."""

        async def run(self):
            print(f"[{self.agent.name}] Ouvindo ordens... Blocklist atual: {self.agent.blocklist}")

            msg = await self.receive(timeout=60)

            if msg:
                print(f"[{self.agent.name}] Ordem recebida de {msg.sender}: {msg.body}")

                if "BLOCK_IP:" in msg.body:
                    ip = msg.body.split(":")[-1]
                    # --- Responsabilidade: Bloquear ---
                    self.agent.blocklist.add(ip)
                    print(f"[{self.agent.name}] SUCESSO: IP {ip} adicionado à blocklist.")

                    # --- Protocolo: Confirmar Execução ---
                    reply = Message(to=str(msg.sender))
                    reply.set_metadata("performative", "inform")
                    reply.body = f"Ação Concluída: IP {ip} bloqueado."
                    await self.send(reply)

                else:
                    print(f"[{self.agent.name}] Ordem não compreendida: {msg.body}")

    async def setup(self):
        print(f"FirewallAgent {self.name} iniciado.")
        # --- Permissão: Acesso à Blocklist ---
        self.blocklist = set()  # Simula a tabela de regras do firewall

        # Template para ouvir ordens do ResponseAgent
        control_template = Template()
        control_template.set_metadata("performative", "request")
        control_template.set_metadata("protocol", "NetworkControl")

        self.add_behaviour(self.CommandReceiver(), control_template)