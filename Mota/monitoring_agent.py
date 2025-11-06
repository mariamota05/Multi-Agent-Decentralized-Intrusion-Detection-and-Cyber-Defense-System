import random
import asyncio
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message
from spade.template import Template


class MonitoringAgent(Agent):
    class UpdateLoadBehaviour(CyclicBehaviour):
        """Atualiza a carga de CPU simulada a cada 10 segundos."""

        async def run(self):
            self.agent.cpu_load += random.randint(-5, 5)
            self.agent.cpu_load = max(0, min(100, self.agent.cpu_load))
            await asyncio.sleep(10)

    class AlertReceiver(CyclicBehaviour):
        """ (CORRIGIDO) Ouve por alertas, RESPONDE ao detetor, e ESCALA para o ResponseAgent."""

        async def run(self):
            print(f"[{self.agent.name}] Aguardando alertas (CPU: {self.agent.cpu_load}%)")

            msg = await self.receive(timeout=60)

            if msg:
                print(f"[{self.agent.name}] ALERTA RECEBIDO de {msg.sender}: '{msg.body}'")

                if self.agent.cpu_load > 80:
                    print(f"[{self.agent.name}] CPU ALTA ({self.agent.cpu_load}%)! Ignorando alerta.")
                    return

                print(f"[{self.agent.name}] Analisando alerta... (aumentando CPU)")
                self.agent.cpu_load += 15
                await asyncio.sleep(3)

                # (Simulação de Análise: 90% de chance de ser real)
                if random.random() < 0.9:
                    print(f"[{self.agent.name}] Análise Concluída: AMEAÇA CONFIRMADA.")

                    # --- MUDANÇA (1): Escalar para o ResponseAgent (como antes) ---
                    escalation_msg = Message(to="incident-response@localhost")
                    escalation_msg.set_metadata("performative", "inform")
                    escalation_msg.set_metadata("protocol", "ConfirmedThreat")
                    escalation_msg.body = f"{msg.body} (Confirmado por {self.name})"
                    await self.send(escalation_msg)
                    print(f"[{self.agent.name}] Ameaça escalada para IncidentResponseAgent.")

                    # --- CORREÇÃO LÓGICA (2): Responder ao DetectionAgent (NOVO) ---
                    print(f"[{self.agent.name}] Enviando confirmação de volta para {msg.sender}.")
                    reply_msg = Message(to=str(msg.sender)) # Envia de volta para o detetor original
                    reply_msg.set_metadata("performative", "inform")
                    reply_msg.body = "CONFIRMADO: A sua ameaça foi validada e escalada." # A palavra "CONFIRMADO" é a chave
                    await self.send(reply_msg)
                    # --- Fim da Correção ---

                else:
                    print(f"[{self.agent.name}] Análise Concluída: Falso Positivo. Ignorando.")
                    # (Opcional: Poderíamos enviar "FALSO POSITIVO" para o DetectionAgent
                    # para que ele aumentasse o seu threshold, tornando-se menos sensível)

            else:
                pass

    async def setup(self):
        print(f"MonitoringAgent {self.name} iniciado.")

        self.cpu_load = random.randint(10, 30)
        self.add_behaviour(self.UpdateLoadBehaviour())

        # Template para ouvir Alertas de Detecção
        alert_template = Template()
        alert_template.set_metadata("performative", "inform")
        alert_template.set_metadata("protocol", "SecurityAlert")

        self.add_behaviour(self.AlertReceiver(), alert_template)