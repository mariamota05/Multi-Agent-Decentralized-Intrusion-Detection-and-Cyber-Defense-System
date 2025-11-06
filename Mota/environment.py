import asyncio
import spade

from detection_agent import DetectionAgent
from monitoring_agent import MonitoringAgent
from firewall_agent import FirewallAgent
from router_agent import RouterAgent
from incident_response_agent import IncidentResponseAgent
from attacker_agent import AttackerAgent


async def main():
    print("Iniciando ambiente completo de Ciberdefesa Multi-Agente...")

    # Lista de agentes a iniciar
    agents_to_start = [
        ("detector1@localhost", "password", DetectionAgent),
        ("monitor@localhost", "password", MonitoringAgent),
        ("firewall@localhost", "password", FirewallAgent),
        ("router@localhost", "password", RouterAgent),
        ("incident-response@localhost", "password", IncidentResponseAgent),
        ("attacker@localhost", "password", AttackerAgent)
    ]

    agents = []

    print("Iniciando agentes de defesa (Monitor, Firewall, Router, Response)...")
    for jid, pwd, AgentClass in agents_to_start:
        if AgentClass != AttackerAgent:  # Inicia o atacante por último
            agent = AgentClass(jid, pwd)
            await agent.start(auto_register=True)
            agents.append(agent)
            print(f"Agente {jid} iniciado.")
            await asyncio.sleep(0.5)

    print("\nIniciando Agente Atacante...")
    attacker = AttackerAgent("attacker@localhost", "password")
    await attacker.start(auto_register=True)
    agents.append(attacker)
    print("Agente attacker@localhost iniciado. O cenário de ataque começou.\n")


    print("--- Simulação a decorrer --- (Pressione Ctrl+C para parar)")

    try:
        while True:
            await asyncio.sleep(10)
            # (Opcional) Pode imprimir o estado aqui, ex: firewall.blocklist
    except KeyboardInterrupt:
        print("\n--- Desligando simulação ---")

    for agent in agents:
        try:
            if agent.is_alive():
                print(f"Parando {agent.name}...")
                await agent.stop()
        except Exception as e:
            print(f"Erro ao parar {agent.name}: {e}")

    print("Ambiente finalizado.")


if __name__ == "__main__":
    spade.run(main())