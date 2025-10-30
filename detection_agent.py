import spade
import random
import asyncio
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour, FSMBehaviour, State
from spade.message import Message
from spade.template import Template

# --- Estados da FSM (Máquina de Estados Finitos) ---
STATE_MONITORING = "MONITORING"
STATE_ALERTING = "ALERTING"
STATE_WAITING = "WAITING"


class DetectionAgent(Agent):
    class SecurityFSM(FSMBehaviour):
        async def on_start(self):
            print(f"[{self.agent.name}] Iniciando FSM de Segurança. Começando no estado MONITORING.")

        async def on_end(self):
            print(f"[{self.agent.name}] FSM de Segurança encerrada.")
            await self.agent.stop()

    # 1. ESTADO: MONITORING (Monitorando)
    class MonitoringState(State):
        async def run(self):
            # A "sensibilidade" do agente.
            print(f"[{self.agent.name}] (Estado: MONITORING) Ouvindo... Limite atual: {self.agent.alert_threshold}")

            # --- Protocolo: Ouvir o "atacante" ---
            # Ouve por 5 segundos
            msg = await self.receive(timeout=5)

            # Simula a receção de um "login falhado"
            if msg and msg.body == "login_attempt: fail":
                self.agent.failed_logins_window.append(1)  # Registra 1 falha
                print(f"[{self.agent.name}] (Estado: MONITORING) Login falhado recebido!")
            else:
                self.agent.failed_logins_window.append(0)  # Registra 0 falhas (passa o tempo)

            # Mantém a janela de tempo (ex: últimos 10 eventos/segundos)
            while len(self.agent.failed_logins_window) > 10:
                self.agent.failed_logins_window.pop(0)

            # --- Responsabilidade: Detetar Anomalia ---
            total_falhas = sum(self.agent.failed_logins_window)

            if total_falhas > self.agent.alert_threshold:
                print(
                    f"[{self.agent.name}] (Estado: MONITORING) AMEAÇA DETETADA! ({total_falhas} falhas > {self.agent.alert_threshold})")
                self.agent.failed_logins_window.clear()  # Limpa a janela
                self.set_next_state(STATE_ALERTING)  # Muda para o estado de Alerta
            else:
                self.set_next_state(STATE_MONITORING)  # Continua monitorando

    # 2. ESTADO: ALERTING (Enviando Alerta)
    class AlertingState(State):
        async def run(self):
            print(f"[{self.agent.name}] (Estado: ALERTING) Enviando alerta para o MonitoringAgent...")

            # --- Protocolo: Enviar Alerta (INFORM) ---
            msg = Message(to="monitor@localhost")  # Envia para o agente de monitoramento
            msg.set_metadata("performative", "inform")
            msg.set_metadata("protocol", "SecurityAlert")  # Boa prática
            msg.body = "ALERTA: Brute Force Suspeito (mais de 5 logins falhados)"

            await self.send(msg)
            print(f"[{self.agent.name}] (Estado: ALERTING) Alerta enviado.")

            # Agora, espera pela confirmação
            self.set_next_state(STATE_WAITING)

            # 3. ESTADO: WAITING (Aguardando Resposta)

    class WaitingState(State):
        async def run(self):
            print(f"[{self.agent.name}] (Estado: WAITING) Aguardando confirmação do Monitor...")

            # --- Protocolo: Receber Resposta ---
            msg = await self.receive(timeout=10)

            if msg:
                print(f"[{self.agent.name}] (Estado: WAITING) Resposta recebida: {msg.body}")

                # --- NOVO (Semana 4): Adaptação de Limite ---
                # Se o monitor confirmar, ficamos mais sensíveis!
                if "CONFIRMADO" in msg.body:
                    print(f"[{self.agent.name}] (Estado: WAITING) Ameaça confirmada! Aumentando sensibilidade.")
                    self.agent.alert_threshold = 3  # Baixa o limite de 5 para 3
                # ----------------------------------------------
            else:
                # Se ninguém confirmar (timeout), voltamos ao normal (menos sensível)
                print(f"[{self.agent.name}] (Estado: WAITING) Nenhuma resposta. Voltando ao normal.")
                self.agent.alert_threshold = 5  # Reseta o limite para 5

            self.set_next_state(STATE_MONITORING)  # Volta ao início

    async def setup(self):
        print(f"DetectionAgent {self.name} iniciado.")

        # --- (Semana 4): Variáveis de estado ---
        self.alert_threshold = 5  # Limite para disparar alerta
        self.failed_logins_window = []  # Janela deslizante de logins
        # -------------------------------------------

        # Configura a Máquina de Estados (FSM)
        fsm = self.SecurityFSM()
        fsm.add_state(name=STATE_MONITORING, state=self.MonitoringState(), initial=True)
        fsm.add_state(name=STATE_ALERTING, state=self.AlertingState())
        fsm.add_state(name=STATE_WAITING, state=self.WaitingState())

        # Adiciona as transições entre os estados
        fsm.add_transition(source=STATE_MONITORING, dest=STATE_MONITORING)
        fsm.add_transition(source=STATE_MONITORING, dest=STATE_ALERTING)
        fsm.add_transition(source=STATE_ALERTING, dest=STATE_WAITING)
        fsm.add_transition(source=STATE_WAITING, dest=STATE_MONITORING)

        self.add_behaviour(fsm)

# --- Para testar este agente individualmente ---
# async def main():
#     agent = DetectionAgent("detector1@localhost", "password")
#     await agent.start(auto_register=True)
#     await spade.wait_until_finished(agent)
# if __name__ == "__main__":
#     spade.run(main())