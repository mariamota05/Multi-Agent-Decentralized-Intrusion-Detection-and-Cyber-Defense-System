"""
Simple workstation/server node using SPADE.

Features:
- Resource Simulation (CPU/Bandwidth)
- Firewall Integration
- Metrics Collection (DDoS Leakage, Overload, Service Uptime)
- Malware Simulation (Vulnerability, Infection, Propagation via 'Worm')
- Health Reporting (For anomaly detection)

Usage:
  Called by environment.py automatically.
"""

import argparse
import asyncio
import datetime
import json
import random
import getpass

import spade
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour, PeriodicBehaviour
from spade.message import Message
from firewall import FirewallBehaviour


def _now_ts():
    return asyncio.get_event_loop().time()


def _log(agent_type: str, jid: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class NodeAgent(Agent):
    """An agent that listens/responds to messages and simulates a computer node."""

    class WormPropagationBehav(PeriodicBehaviour):
        """
        WORM BEHAVIOUR
        Corre apenas se o nó estiver infetado.
        Tenta espalhar a carga (ataque) para vizinhos de forma furtiva.
        """
        async def run(self):
            # Se o nó for limpo ou morrer, este comportamento para
            if not self.agent.get("is_infected") or self.agent.get("node_dead"):
                self.kill()
                return

            # Tenta encontrar o router para enviar a mensagem
            router = self.agent.get("router")
            if not router:
                return

            # --- Encontrar um Alvo Aleatório ---
            # Tenta atacar o "irmão" (outro nó no mesmo router)
            my_jid_str = str(self.agent.jid)
            try:
                base, domain = my_jid_str.split('@')
                router_prefix, node_part = base.split('_node')
                my_index = int(node_part)
                # Ataca o outro nó (0 -> 1, 1 -> 0) - Lógica simples para 2 nós/router
                peer_index = 1 - my_index
                target_node = f"{router_prefix}_node{peer_index}@{domain}"
            except Exception:
                return

            # --- A Mensagem-Armadilha Furtiva ---
            msg = Message(to=router)
            msg.set_metadata("dst", target_node)
            msg.set_metadata("protocol", "worm-payload")

            # O corpo parece benigno (PING)
            msg.body = "PING"

            # A "bomba" de CPU: Causa 20% de carga na vítima por 10 segundos
            task_data = {
                "cpu_load": 20.0,
                "duration": 10.0
            }
            msg.set_metadata("task", json.dumps(task_data))

            await self.send(msg)

    class RecvBehav(CyclicBehaviour):
        async def run(self):
            msg = await self.receive(timeout=10)
            if msg:
                # 1. Verificar se o nó está morto (Crash por CPU)
                is_dead = self.agent.get("node_dead") or False
                if is_dead:
                    return

                # 2. Verificar Firewall
                fw = self.agent.get("firewall")
                if fw:
                    allowed = await fw.allow_message(msg)
                    if not allowed:
                        return

                # --- MÉTRICAS DDOS: LEAKAGE ---
                # Se chegou aqui, a firewall deixou passar.
                protocol = msg.get_metadata("protocol")
                if protocol == "attack":
                    count = self.agent.get("ddos_packets_received") or 0
                    self.agent.set("ddos_packets_received", count + 1)

                body_text = (msg.body or "").strip()
                body_lower = body_text.lower()

                # --- LÓGICA DE MALWARE: VULNERABILIDADE ---
                # Se receber uma keyword de infeção, torna-se o Paciente Zero
                if not self.agent.get("is_infected"):
                    infection_keywords = ["trojan", "worm", "exploit", "ransomware"]
                    for kw in infection_keywords:
                        if kw in body_lower:
                            _log("NodeAgent", str(self.agent.jid), "[!!!] VULNERABILIDADE EXPLORADA. O nó está agora infetado.")
                            self.agent.set("is_infected", True)
                            # Iniciar a propagação (Worm)
                            behav = self.agent.WormPropagationBehav(period=10.0)
                            self.agent.add_behaviour(behav)
                            break

                # --- PROCESSAMENTO DE TAREFAS (CPU LOAD) ---
                task_info = None
                try:
                    if msg.metadata and "task" in msg.metadata:
                        raw = msg.metadata.get("task")
                        task_info = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    task_info = None

                if task_info:
                    active = self.agent.get("active_tasks") or {}
                    counter = self.agent.get("task_counter") or 0
                    counter += 1
                    tid = f"t{counter}-{int(_now_ts())}"
                    self.agent.set("task_counter", counter)

                    duration = float(task_info.get("duration", 1.0))
                    load = float(task_info.get("cpu_load", 0.0))

                    active[tid] = {"end": _now_ts() + duration, "load": load}
                    self.agent.set("active_tasks", active)

                    if load > 5.0:
                         _log("NodeAgent", str(self.agent.jid), f"Scheduled task {tid}: duration={duration} load={load}")

                # --- TRATAMENTO DE MENSAGENS ---

                if body_text.startswith(("BLOCK_JID:", "RATE_LIMIT:", "TEMP_BLOCK:", "SUSPEND_ACCESS:", "CLEAN_INFECTION:")):
                    # Comandos da Firewall/Resposta
                    if fw:
                        control_msg = Message(to=str(self.agent.jid))
                        control_msg.set_metadata("protocol", "firewall-control")
                        control_msg.body = body_text
                        control_msg.sender = msg.sender
                        await fw._handle_control(control_msg)

                elif body_text.upper() == "PING":
                    # MÉTRICA: Serviço Legítimo
                    pings = self.agent.get("pings_answered") or 0
                    self.agent.set("pings_answered", pings + 1)

                    # Enviar PONG via Router
                    router = self.agent.get("router")
                    original_sender = msg.get_metadata("original_sender") or str(msg.sender)

                    if router:
                        reply = Message(to=router)
                        reply.set_metadata("dst", original_sender)
                        reply.body = "PONG"
                        await self.send(reply)
                    else:
                        reply = Message(to=str(msg.sender))
                        reply.body = "PONG"
                        await self.send(reply)

                elif body_text.startswith("REQUEST:"):
                    content = body_text.split("REQUEST:", 1)[1]
                    router = self.agent.get("router")
                    original_sender = msg.get_metadata("original_sender") or str(msg.sender)

                    reply_body = f"RESPONSE: processed '{content.strip()}'"

                    if router:
                        reply = Message(to=router)
                        reply.set_metadata("dst", original_sender)
                        reply.body = reply_body
                        await self.send(reply)
                    else:
                        reply = Message(to=str(msg.sender))
                        reply.body = reply_body
                        await self.send(reply)

    class ResourceBehav(CyclicBehaviour):
        async def run(self):
            # 1. Morte do Nó
            if self.agent.get("node_dead"):
                self.kill()
                return

            now = _now_ts()
            active = self.agent.get("active_tasks") or {}

            # Remover tarefas terminadas
            active = {k: v for k, v in active.items() if v.get("end", 0) > now}
            self.agent.set("active_tasks", active)

            # Calcular CPU base + Tarefas
            try:
                base_cpu = float(self.agent.get("base_cpu") or 10.0)
            except Exception:
                base_cpu = 10.0

            extra_cpu = sum(float(info.get("load", 0.0)) for info in active.values())

            # 2. Carga Parasita (Sintoma da Infeção)
            infection_load = 20.0 if self.agent.get("is_infected") else 0.0

            send_adj = float(getattr(self.agent, "_send_adjust", 0.0) or 0.0)

            total_cpu = base_cpu + extra_cpu + infection_load + send_adj
            cpu_usage = min(100.0, total_cpu)

            try:
                 base_bw = float(self.agent.get("base_bw") or 5.0)
            except:
                 base_bw = 5.0

            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", min(100.0, base_bw + extra_cpu * 0.2))
            current_peak = self.agent.get("cpu_peak") or 0.0
            if cpu_usage > current_peak:
                self.agent.set("cpu_peak", cpu_usage)

            # 3. Métrica de Sobrecarga
            if cpu_usage > 90.0:
                ticks = self.agent.get("cpu_overload_ticks") or 0
                self.agent.set("cpu_overload_ticks", ticks + 1)

            # 4. Verificar Morte (Crash a 100%)
            if cpu_usage >= 100.0:
                _log("NodeAgent", str(self.agent.jid), "FATAL: CPU a 100%. O nó CRASHOU e está offline.")
                self.agent.set("node_dead", True)
                self.agent.set("active_tasks", {})
                self.agent.set("cpu_usage", 0.0)
                router = self.agent.get("router")
                if router:
                    death_msg = Message(to=router)
                    death_msg.set_metadata("protocol", "node-death")
                    death_msg.body = f"NODE_DEATH: {str(self.agent.jid)}"
                    await self.send(death_msg)
                self.kill()
                return

            # 5. Relatório de Saúde (CORRIGIDO AQUI)
            last_report = self.agent.get("last_health_report") or 0
            if now - last_report > 5.0:
                self.agent.set("last_health_report", now)
                try:
                    router_jid = self.agent.get("router")
                    if router_jid:
                        monitor_jid = f"monitor{router_jid.split('router')[1].split('@')[0]}@{router_jid.split('@')[1]}"
                        msg = Message(to=monitor_jid)
                        msg.set_metadata("protocol", "health-report")
                        msg.body = f"CPU:{cpu_usage}"
                        await self.send(msg)
                except Exception:
                    pass

            if cpu_usage > 15.0:
                _log("NodeAgent", str(self.agent.jid), f"Load: CPU={cpu_usage:.1f}% (Infected={self.agent.get('is_infected')})")

            await asyncio.sleep(1.0)

    async def setup(self):
        _log("NodeAgent", str(self.jid), "starting...")

        self.set("is_infected", False)
        self.set("node_dead", False)
        self.set("task_counter", 0)
        self.set("cpu_peak", 0.0)
        self.set("ddos_packets_received", 0)
        self.set("cpu_overload_ticks", 0)
        self.set("pings_answered", 0)
        self.set("base_cpu", 10.0)
        self.set("base_bw", 5.0)
        self.set("active_tasks", {})

        fw = FirewallBehaviour()
        self.add_behaviour(fw)
        self.set("firewall", fw)

        self.add_behaviour(self.RecvBehav())
        self.add_behaviour(self.ResourceBehav())

        peers = self.get("peers") or []
        local_nodes = set(peers)
        local_nodes.add(str(self.jid))
        self.set("local_nodes", local_nodes)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jid", required=True, help="Agent JID")
    parser.add_argument("--password", required=True, help="Agent password")
    parser.add_argument("--peers", default="", help="Comma-separated peers")
    parser.add_argument("--heartbeat", type=int, default=0)
    parser.add_argument("--no-auto-register", dest="auto_register", action="store_false")
    args = parser.parse_args()

    agent = NodeAgent(args.jid, args.password)
    peers = [p.strip() for p in args.peers.split(",") if p.strip()]
    agent.set("peers", peers)

    if peers:
        agent.set("router", peers[0])

    try:
        await agent.start(auto_register=args.auto_register)
    except Exception as e:
        print(f"Failed to start {args.jid}: {e}")
        return

    print(f"Node {args.jid} started.")
    try:
        await spade.wait_until_finished(agent)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        await agent.stop()

if __name__ == "__main__":
    spade.run(main())