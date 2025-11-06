from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message
from spade.template import Template


class IncidentResponseAgent(Agent):
    class ThreatHandler(CyclicBehaviour):
        """Ouve por ameaças confirmadas e decide a ação de mitigação."""

        async def run(self):
            print(f"[{self.agent.name}] Aguardando ameaças confirmadas do Monitor...")

            # Template para ouvir *apenas* do MonitoringAgent
            msg = await self.receive(timeout=60)

            if msg:
                print(f"[{self.agent.name}] AMEAÇA CONFIRMADA RECEBIDA: {msg.body}")

                # --- Responsabilidade: Decidir Estratégia ---
                # Esta é a lógica de "Activity" privada do agente
                ip_suspeito = "1.2.3.4"  # (Simulado - o Monitor deveria enviar isto)

                if "Brute Force" in msg.body:
                    print(f"[{self.agent.name}] Decisão: É Brute Force. Vou BLOQUEAR o IP {ip_suspeito}.")
                    # --- Protocolo: Enviar Ordem (REQUEST) ---
                    await self.agent.send_control_request("firewall@localhost", f"BLOCK_IP:{ip_suspeito}")

                elif "Malware" in msg.body:
                    print(f"[{self.agent.name}] Decisão: É Malware. Vou REROTEAR o IP {ip_suspeito}.")
                    # --- Protocolo: Enviar Ordem (REQUEST) ---
                    await self.agent.send_control_request("router@localhost", f"REROUTE_IP:{ip_suspeito}")

            else:
                pass  # print(f"[{self.agent.name}] Nenhum incidente confirmado.")

    async def send_control_request(self, agent_jid, command):
        """Envia uma ordem para um agente de controle (Firewall/Router)."""
        print(f"[{self.name}] Enviando comando '{command}' para {agent_jid}")
        msg = Message(to=agent_jid)
        msg.set_metadata("performative", "request")
        msg.set_metadata("protocol", "NetworkControl")
        msg.body = command
        await self.send(msg)

        # (Num sistema real, ele esperaria uma confirmação 'INFORM' do Firewall/Router)

    async def setup(self):
        print(f"IncidentResponseAgent {self.name} iniciado.")

        # Template para ouvir o Monitor
        threat_template = Template()
        threat_template.set_metadata("performative", "inform")
        threat_template.set_metadata("protocol", "ConfirmedThreat")  # Novo protocolo

        self.add_behaviour(self.ThreatHandler(), threat_template)