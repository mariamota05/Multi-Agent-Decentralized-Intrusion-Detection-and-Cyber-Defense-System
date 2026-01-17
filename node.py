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
    """Return a monotonic timestamp from the asyncio event loop.

    Used to schedule and check timed tasks inside behaviours. Returns a
    float (seconds) compatible with values stored in behaviour state.
    """
    return asyncio.get_event_loop().time()


def _log(agent_type: str, jid: str, msg: str) -> None:
    """Log a message with a time prefix and agent identity.

    Args:
    - agent_type (str): short label for the agent class (e.g. 'NodeAgent').
    - jid (str): agent JID string.
    - msg (str): human-readable message body.
    """
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{agent_type} {jid}] {msg}")


class NodeAgent(Agent):
    """An agent that listens/responds to messages and simulates a computer node."""

    class LateralMovementBehaviour(PeriodicBehaviour):
        """
        INSIDER THREAT: Lateral Movement
        Runs when node is compromised by insider attack.
        Spreads backdoor to peer nodes in the subnet.
        """

        async def run(self):
            """Attempt to spread a backdoor to peers in the local subnet.

            Runs periodically while the agent is marked `compromised`. Selects
            targets based on `compromised_intensity`, sends lateral-spread
            messages via the router and updates `infected_peers` state.

            Propagation details:
            - Success rate is proportional to attacker `intensity` (up to 95%).
            - Targets are chosen randomly from uncompromised peers in the subnet.
            - High intensity (> 7) can target multiple peers per cycle.
            """
            # Stop if node is cleaned
            if not self.agent.get("compromised"):
                self.kill()
                return

            router = self.agent.get("router")
            if not router:
                return

            # Get peers in the same subnet
            subnet_peers = self.agent.get("subnet_peers") or []
            if not subnet_peers:
                return

            # Probabilistic lateral spread based on attacker skill
            intensity = self.agent.get("compromised_intensity") or 6
            spread_success_rate = min(95, intensity * 10)  # 10% at intensity=1, 95% at intensity=9+

            import random
            if random.randint(1, 100) > spread_success_rate:
                # Failed to spread - insufficient privileges, detected by local security, etc.
                _log("NodeAgent", str(self.agent.jid),
                     f"[SPREAD FAILED] Lateral movement blocked (success rate: {spread_success_rate}%)")
                return

            # Filter out already compromised targets
            compromised_by_me = self.agent.get("infected_peers") or set()
            available_targets = [p for p in subnet_peers if p not in compromised_by_me]

            if not available_targets:
                # All peers already compromised
                return

            # Pick target(s) based on intensity
            targets_count = 1 if intensity < 7 else min(2, len(available_targets))

            import random
            targets = random.sample(available_targets, min(targets_count, len(available_targets)))

            for target in targets:
                # Send lateral spread message
                msg = Message(to=router)
                msg.set_metadata("dst", target)
                msg.set_metadata("protocol", "attack")
                msg.set_metadata("spread_intensity", str(intensity))

                backdoor_type = self.agent.get("backdoor_type") or "insider_backdoor"
                msg.body = f"LATERAL_SPREAD:{backdoor_type}"

                await self.send(msg)

                # Track who we've infected
                compromised_by_me.add(target)
                self.agent.set("infected_peers", compromised_by_me)

                _log("NodeAgent", str(self.agent.jid),
                     f"[SPREAD] Lateral movement to {target} (intensity={intensity})")

    class WormPropagationBehav(PeriodicBehaviour):
        """
        MALWARE: WORM BEHAVIOUR
        Corre apenas se o nó estiver infetado com malware.
        Tenta espalhar a carga (ataque) para vizinhos de forma furtiva.
        """

        async def run(self):
            """Periodically send stealth 'worm' payloads when infected.

            Crafts a benign-looking `PING` with `task` metadata that causes CPU
            load on the recipient. Targets a sibling node on the same router
            when possible.

            The payload simulates a persistent CPU-intensive malware process.
            """
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
            """Main receive loop for incoming messages.

            Handles:
            1. **Pre-Checks**: Dead node, self-isolation (blocks all non-critical messages), and backlog mode (prioritizes critical messages).
            2. **Firewall Filtering**: Uses `FirewallBehaviour.allow_message` to enforce rules.
            3. **Metrics**: Tracks leaked DDoS packets.
            4. **Infection Logic**: Handles initial malware infection (Phase 1/Malware) and persistent threat installation (Insider).
            5. **Task Processing**: Schedules CPU load from messages with `task` metadata, triggering **immediate self-isolation** if CPU exceeds 65% on task addition.
            6. **Control Messages**: Processes `CURE_INFECTION`, `FORENSIC_CLEAN`, and firewall commands, applying probabilistic success rates based on attacker intensity.
            7. **Service Response**: Replies to `PING` and `REQUEST` messages.
            """
            msg = await self.receive(timeout=10)
            if msg:
                # 1. Verificar se o nó está morto (Crash por CPU)
                is_dead = self.agent.get("node_dead") or False
                if is_dead:
                    return

                # 2. Check for self-isolation (reject all EXCEPT cure messages and health checks during malware containment)
                self_isolated = self.agent.get("self_isolated") or False
                if self_isolated:
                    # Allow CURE, FORENSIC_CLEAN, and HEALTH_CHECK to break through isolation
                    protocol = msg.get_metadata("protocol")
                    body_lower = (msg.body or "").lower()
                    cure_keywords = {"cure_infection", "forensic_clean"}

                    is_cure = (protocol == "cure" or
                               any(kw in body_lower for kw in cure_keywords))
                    is_health_check = (protocol == "health-check" or body_lower.startswith("ping"))

                    if not is_cure and not is_health_check:
                        return  # Block everything except cure and health checks during isolation

                # 2.5. Check for backlog mode (reject NON-CRITICAL messages during legitimate overload)
                backlog_mode = self.agent.get("backlog_mode") or False
                if backlog_mode:
                    protocol = msg.get_metadata("protocol")
                    body_lower = (msg.body or "").lower()

                    # Allow CRITICAL messages through (cure, firewall controls, cleanup)
                    critical_protocols = {"firewall-control", "cure"}
                    critical_keywords = {"cure_infection", "forensic_clean", "block_jid", "rate_limit"}

                    is_critical = (protocol in critical_protocols or
                                   any(kw in body_lower for kw in critical_keywords))

                    if not is_critical:
                        # Drop non-critical messages to reduce backlog
                        return

                # 3. Verificar Firewall
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
                            # Store infection details including attacker intensity
                            attacker_intensity = int(msg.get_metadata("attacker_intensity") or 5)
                            self.agent.set("attacker_intensity", attacker_intensity)
                            _log("NodeAgent", str(self.agent.jid),
                                 f"[!!!] VULNERABILIDADE EXPLORADA. O nó está agora infetado (intensity={attacker_intensity}).")
                            self.agent.set("is_infected", True)
                            # Iniciar a propagação (Worm)
                            behav = self.agent.WormPropagationBehav(period=10.0)
                            self.agent.add_behaviour(behav)
                            break

                # --- PROCESSAMENTO DE TAREFAS (CPU LOAD) ---
                # Skip CPU processing for PING during self-isolation to prevent crashes
                self_isolated = self.agent.get("self_isolated") or False
                is_ping = body_text.upper() == "PING"

                if self_isolated and is_ping:
                    # Process PING without CPU cost during isolation
                    task_info = None
                else:
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

                    # IMMEDIATE CPU CHECK: Calculate CPU right after task addition to detect infection before accepting more messages
                    base_cpu = float(self.agent.get("base_cpu") or 10.0)
                    extra_cpu = sum(float(info.get("load", 0.0)) for info in active.values())
                    infection_load = 20.0 if self.agent.get("is_infected") else 0.0
                    send_adj = float(getattr(self.agent, "_send_adjust", 0.0) or 0.0)
                    current_cpu = min(100.0, base_cpu + extra_cpu + infection_load + send_adj)

                    # Check if we crossed the infection detection threshold
                    if current_cpu > 65.0 and not self.agent.get("self_isolated"):
                        num_tasks = len(active)
                        avg_cpu_per_task = (extra_cpu / num_tasks) if num_tasks > 0 else current_cpu

                        # Infection signature: avg > 15% (normal=8.5%, infected=24%)
                        if avg_cpu_per_task > 15.0:
                            _log("NodeAgent", str(self.agent.jid),
                                 f"[!] IMMEDIATE DETECTION: CPU={current_cpu:.1f}% tasks={num_tasks} avg={avg_cpu_per_task:.1f}% - SELF-ISOLATING")
                            self.agent.set("self_isolated", True)
                            self.agent.set("isolation_start", _now_ts())
                            # Signal ResourceBehav to send alert on next cycle
                            self.agent.set("pending_infection_alert", True)

                # --- TRATAMENTO DE MENSAGENS ---

                if body_text.startswith("INFECT:"):
                    # MALWARE INFECTION: Stealth malware from attacker
                    protocol = msg.get_metadata("protocol") if msg.metadata else None
                    malware_type = body_text.split("INFECT:", 1)[1].strip()
                    was_infected = self.agent.get("is_infected") or False

                    if protocol == "malware-infection":
                        if not was_infected:
                            # Store infection details including attacker intensity
                            attacker_intensity = int(msg.get_metadata("attacker_intensity") or 5)
                            self.agent.set("is_infected", True)
                            self.agent.set("malware_type", malware_type)
                            self.agent.set("attacker_intensity", attacker_intensity)

                            # Get original attacker (not the router that forwarded it)
                            infection_source = msg.get_metadata("original_sender") or str(msg.sender)
                            self.agent.set("infection_source", infection_source)

                            _log("NodeAgent", str(self.agent.jid),
                                 f"INFECTED with {malware_type} (intensity={attacker_intensity}) - Persistent +20% CPU overhead")

                            # Notify monitoring agent about infection
                            router = self.agent.get("router")
                            if router:
                                alert_msg = Message(to=router)
                                alert_msg.set_metadata("protocol", "malware-infection")
                                alert_msg.set_metadata("attacker_intensity", str(attacker_intensity))
                                alert_msg.body = f"INFECTED:{malware_type}"
                                await self.send(alert_msg)
                                _log("NodeAgent", str(self.agent.jid),
                                     f"Notified router about infection")

                            # Start worm propagation
                            behav = self.agent.WormPropagationBehav(period=10.0)
                            self.agent.add_behaviour(behav)
                        else:
                            _log("NodeAgent", str(self.agent.jid),
                                 f"Already infected, attempted re-infection with {malware_type}")
                    else:
                        _log("NodeAgent", str(self.agent.jid),
                             f"INFECT message received but protocol={protocol} (expected 'malware-infection')")

                elif body_text.startswith("DATA_EXFILTRATION:"):
                    # INSIDER THREAT Phase 2: Data Exfiltration (bandwidth overhead)
                    already_exfiltrating = self.agent.get("exfiltration_active") or False
                    if not already_exfiltrating:
                        attacker_intensity = int(msg.get_metadata("attacker_intensity") or 6)
                        exfiltration_source = msg.get_metadata("original_sender") or str(msg.sender)
                        bw_overhead = attacker_intensity * 5.0

                        self.agent.set("exfiltration_active", True)
                        self.agent.set("exfiltration_bandwidth", bw_overhead)
                        self.agent.set("exfiltration_source", exfiltration_source)

                        _log("NodeAgent", str(self.agent.jid),
                             f"[!] DATA EXFILTRATION STARTED: +{bw_overhead:.0f}% bandwidth overhead (intensity={attacker_intensity})")

                elif body_text.startswith("BACKDOOR_INSTALL:"):
                    # INSIDER THREAT Phase 3: Backdoor Installation (enables lateral movement)
                    already_compromised = self.agent.get("compromised") or False
                    if not already_compromised:
                        backdoor_type = body_text.split("BACKDOOR_INSTALL:", 1)[1].strip()
                        attacker_intensity = int(msg.get_metadata("attacker_intensity") or 6)
                        compromised_by = msg.get_metadata("original_sender") or str(msg.sender)

                        self.agent.set("compromised", True)
                        self.agent.set("backdoor_type", backdoor_type)
                        self.agent.set("compromised_by", compromised_by)
                        self.agent.set("compromised_intensity", attacker_intensity)

                        _log("NodeAgent", str(self.agent.jid),
                             f"[!!] BACKDOOR INSTALLED: {backdoor_type} (intensity={attacker_intensity}) - Lateral movement enabled")

                        # Start lateral movement behavior
                        spread_period = max(5.0, 30.0 - (attacker_intensity * 2.5))
                        lateral_behav = self.agent.LateralMovementBehaviour(period=spread_period)
                        self.agent.add_behaviour(lateral_behav)
                        self.agent.set("lateral_movement_active", True)

                        _log("NodeAgent", str(self.agent.jid),
                             f"Lateral movement period: {spread_period:.1f}s (will spread to subnet peers)")

                elif body_text.startswith("LATERAL_SPREAD:"):
                    # INSIDER THREAT: Lateral spread from compromised peer (trusted source)
                    already_compromised = self.agent.get("compromised") or False
                    if not already_compromised:
                        backdoor_type = body_text.split("LATERAL_SPREAD:", 1)[1].strip()
                        source_node = str(msg.sender)
                        attacker_intensity = int(msg.get_metadata("spread_intensity") or 7)

                        # Probabilistic lateral infection success (network security, endpoint protection, etc.)
                        import random
                        infection_success_rate = min(90, 40 + (attacker_intensity * 5))  # 45% to 90%

                        if random.randint(1, 100) > infection_success_rate:
                            _log("NodeAgent", str(self.agent.jid),
                                 f"[BLOCKED] Lateral infection attempt from {source_node} blocked by local security ({infection_success_rate}% success rate)")
                            return

                        self.agent.set("compromised", True)
                        self.agent.set("backdoor_type", backdoor_type)
                        self.agent.set("compromised_by", source_node)
                        self.agent.set("compromised_intensity", attacker_intensity)

                        # Also start exfiltration
                        bw_overhead = attacker_intensity * 5.0
                        self.agent.set("exfiltration_active", True)
                        self.agent.set("exfiltration_bandwidth", bw_overhead)

                        _log("NodeAgent", str(self.agent.jid),
                             f"[!!] LATERAL INFECTION from {source_node}: {backdoor_type} installed")

                        # Start lateral movement to continue spreading
                        spread_period = max(5.0, 30.0 - (attacker_intensity * 2.5))
                        lateral_behav = self.agent.LateralMovementBehaviour(period=spread_period)
                        self.agent.add_behaviour(lateral_behav)
                        self.agent.set("lateral_movement_active", True)

                elif body_text.startswith(("BLOCK_JID:", "RATE_LIMIT:", "TEMP_BLOCK:", "SUSPEND_ACCESS:")):
                    # Comandos da Firewall/Resposta
                    if fw:
                        control_msg = Message(to=str(self.agent.jid))
                        control_msg.set_metadata("protocol", "firewall-control")
                        control_msg.body = body_text
                        control_msg.sender = msg.sender
                        await fw._handle_control(control_msg)

                elif body_text.startswith("CURE_INFECTION"):
                    # HARD RESET: Probabilistic malware removal based on attacker intensity
                    is_infected = self.agent.get("is_infected") or False
                    if is_infected:
                        attacker_intensity = self.agent.get("attacker_intensity") or 5
                        malware_type = self.agent.get("malware_type") or "unknown"

                        # Calculate cure success rate: 100 - (intensity × 7) → 30% to 93%
                        base_success = 100 - (attacker_intensity * 7)
                        cure_success_rate = max(30, min(95, base_success))

                        _log("NodeAgent", str(self.agent.jid),
                             f"HARD RESET INITIATED: Attempting to remove {malware_type} (intensity={attacker_intensity}, success_rate={cure_success_rate:.0f}%)")

                        # Probabilistic cure
                        import random
                        if random.random() * 100 < cure_success_rate:
                            # SUCCESS: Perform hard reset
                            active_tasks = self.agent.get("active_tasks") or {}
                            num_tasks_cleared = len(active_tasks)

                            # Clear all tasks
                            self.agent.set("active_tasks", {})

                            # Remove infection
                            self.agent.set("is_infected", False)
                            self.agent.set("malware_type", None)
                            self.agent.set("attacker_intensity", None)
                            self.agent.set("infection_source", None)

                            # End self-isolation if active
                            self.agent.set("self_isolated", False)

                            _log("NodeAgent", str(self.agent.jid),
                                 f"[OK] HARD RESET COMPLETE: {malware_type} removed, {num_tasks_cleared} tasks cleared, resources reset")
                        else:
                            # FAILURE: Malware has rootkit/persistence, hard reset failed
                            _log("NodeAgent", str(self.agent.jid),
                                 f"[FAIL] HARD RESET FAILED: {malware_type} has advanced persistence mechanisms (rootkit/firmware)")
                    else:
                        _log("NodeAgent", str(self.agent.jid), "Not infected, hard reset command ignored")

                elif body_text.startswith("FORENSIC_CLEAN"):
                    # FORENSIC CLEAN: Probabilistic insider threat removal based on intensity
                    is_compromised = self.agent.get("compromised") or False

                    if is_compromised:
                        intensity = self.agent.get("compromised_intensity") or 6
                        backdoor_type = self.agent.get("backdoor_type") or "unknown_backdoor"

                        # Calculate clean success rate: 100 - (intensity × 6) → 40% to 94%
                        base_success = 100 - (intensity * 6)
                        clean_success_rate = max(40, min(95, base_success))

                        _log("NodeAgent", str(self.agent.jid),
                             f"FORENSIC CLEAN INITIATED: Attempting to remove {backdoor_type} (intensity={intensity}, success_rate={clean_success_rate:.0f}%)")

                        import random
                        if random.random() * 100 < clean_success_rate:
                            # SUCCESS: Remove backdoor
                            self.agent.set("compromised", False)
                            self.agent.set("backdoor_type", None)
                            self.agent.set("compromised_by", None)
                            self.agent.set("compromised_intensity", None)
                            self.agent.set("exfiltration_active", False)
                            self.agent.set("exfiltration_bandwidth", 0.0)
                            self.agent.set("exfiltration_source", None)
                            self.agent.set("lateral_movement_active", False)
                            self.agent.set("infected_peers", set())

                            _log("NodeAgent", str(self.agent.jid),
                                 f"[OK] FORENSIC CLEAN COMPLETE: {backdoor_type} removed, system restored")
                        else:
                            # FAILURE: Backdoor persists
                            _log("NodeAgent", str(self.agent.jid),
                                 f"[FAIL] FORENSIC CLEAN FAILED: {backdoor_type} has rootkit-level persistence")
                    else:
                        _log("NodeAgent", str(self.agent.jid), "Not compromised, forensic clean command ignored")

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
            """Periodic resource accounting behaviour.

            Recomputes CPU/bandwidth usage, detects overload/infection
            signatures, triggers containment (self-isolate/backlog) and sends
            alerts to the router/monitor. Updates agent state keys such as
            `cpu_usage`, `bandwidth_usage` and `cpu_overload_ticks`.

            Logic flow:
            1. Clean up expired tasks.
            2. Calculate current CPU load (base + tasks + **malware overhead**).
            3. Calculate current Bandwidth (base + traffic + **exfiltration overhead**).
            4. **Overload Check (CPU > 70%)**:
                - **Infection Signature (Avg Task Load > 15%)**: Trigger self-isolation and send alert.
                - **Normal Overload (Avg Task Load <= 15%)**: Trigger backlog mode.
            5. **Recovery Check (CPU < 40%)**: Ends self-isolation or backlog mode.
            6. **Fatal Check (CPU >= 100%)**: Sets `node_dead` and sends `NODE_DEATH` alert.
            7. **Health Report**: Sends periodic CPU report to the monitor.
            """
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

            # Add exfiltration bandwidth overhead (insider threat Phase 2)
            exfiltration_bw = float(self.agent.get("exfiltration_bandwidth") or 0.0)

            self.agent.set("cpu_usage", cpu_usage)
            self.agent.set("bandwidth_usage", min(100.0, base_bw + extra_cpu * 0.2 + exfiltration_bw))
            current_peak = self.agent.get("cpu_peak") or 0.0
            if cpu_usage > current_peak:
                self.agent.set("cpu_peak", cpu_usage)

            # 3. Métrica de Sobrecarga
            if cpu_usage > 90.0:
                ticks = self.agent.get("cpu_overload_ticks") or 0
                self.agent.set("cpu_overload_ticks", ticks + 1)

            # 3.5. SANITY CHECK - Immediate detection at 70% CPU threshold (buffer before 100% crash)
            if cpu_usage > 70.0:
                num_tasks = len(active)
                total_task_load = extra_cpu  # Already calculated above

                # Calculate average CPU per task
                avg_cpu_per_task = (total_task_load / num_tasks) if num_tasks > 0 else cpu_usage

                # SCENARIO 1: High CPU per task → Infection detected
                # Infection signature: avg > 15% (Normal load max ~10%, Infection adds 20% flat)
                if avg_cpu_per_task > 15.0 or (num_tasks == 0 and cpu_usage > 70.0):
                    # CRITICAL: Self-isolate immediately to prevent crash while waiting for cure
                    # This must happen EVERY time we detect infection, not just when alerting
                    self_isolated = self.agent.get("self_isolated") or False
                    if not self_isolated:
                        _log("NodeAgent", str(self.agent.jid),
                             f"INFECTION DETECTED: CPU={cpu_usage:.1f}% tasks={num_tasks} avg/task={avg_cpu_per_task:.1f}%")
                        _log("NodeAgent", str(self.agent.jid),
                             f"Normal avg is 5-10%, detected {avg_cpu_per_task:.1f}% - SELF-ISOLATING NOW")

                        self.agent.set("self_isolated", True)
                        self.agent.set("isolation_start", now)

                    # Send threat alert (rate-limited to avoid spam)
                    last_alert = self.agent.get("last_infection_alert") or 0
                    if now - last_alert > 10.0:
                        router = self.agent.get("router")
                        if router:
                            alert_msg = Message(to=router)
                            alert_msg.set_metadata("protocol", "threat-alert")
                            alert_msg.set_metadata("threat_type", "suspected_malware")
                            alert_msg.set_metadata("dst", str(self.agent.jid))  # I am the victim needing cure

                            # Include infection source as offender if known
                            infection_source = self.agent.get("infection_source") or "unknown"
                            alert_msg.set_metadata("offender", infection_source)

                            alert_msg.body = f"INFECTED:CPU={cpu_usage:.1f}%,tasks={num_tasks},avg={avg_cpu_per_task:.1f}%"
                            await self.send(alert_msg)
                            _log("NodeAgent", str(self.agent.jid), "Sent infection alert to router/monitor")
                            self.agent.set("last_infection_alert", now)

                # SCENARIO 2: Normal CPU per task → Just overloaded with legitimate work
                # Use backlog mode instead of full isolation to prevent crash
                # This allows CURE_INFECTION and critical messages through while reducing load
                elif avg_cpu_per_task <= 15.0:
                    backlog_mode = self.agent.get("backlog_mode") or False
                    if not backlog_mode:
                        _log("NodeAgent", str(self.agent.jid),
                             f"HIGH LOAD: CPU={cpu_usage:.1f}% tasks={num_tasks} avg/task={avg_cpu_per_task:.1f}%")
                        _log("NodeAgent", str(self.agent.jid),
                             "Normal task overhead - entering BACKLOG MODE (will prioritize critical messages)")
                        self.agent.set("backlog_mode", True)
                        self.agent.set("backlog_start", now)

            # Check if we can end self-isolation OR backlog mode
            elif cpu_usage < 40.0:
                self_isolated = self.agent.get("self_isolated") or False
                backlog_mode = self.agent.get("backlog_mode") or False

                if self_isolated:
                    isolation_start = self.agent.get("isolation_start") or now
                    duration = now - isolation_start
                    _log("NodeAgent", str(self.agent.jid),
                         f"Infection contained (CPU={cpu_usage:.1f}%) - Ending self-isolation after {duration:.1f}s")
                    self.agent.set("self_isolated", False)

                if backlog_mode:
                    backlog_start = self.agent.get("backlog_start") or now
                    duration = now - backlog_start
                    _log("NodeAgent", str(self.agent.jid),
                         f"Backlog cleared (CPU={cpu_usage:.1f}%) - Ending backlog mode after {duration:.1f}s")
                    self.agent.set("backlog_mode", False)

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
                        # Assumes monitor JID structure based on router JID: router0@domain -> monitor0@domain
                        monitor_jid = f"monitor{router_jid.split('router')[1].split('@')[0]}@{router_jid.split('@')[1]}"
                        msg = Message(to=monitor_jid)
                        msg.set_metadata("protocol", "health-report")
                        msg.body = f"CPU:{cpu_usage}"
                        await self.send(msg)
                except Exception:
                    pass

            if cpu_usage > 15.0:
                bw_usage = self.agent.get("bandwidth_usage") or 0.0
                _log("NodeAgent", str(self.agent.jid),
                     f"Load: CPU={cpu_usage:.1f}% BW={bw_usage:.1f}% (Infected={self.agent.get('is_infected')})")

            # Check if immediate CPU check was requested (task just added)
            immediate_check = self.agent.get("immediate_cpu_check") or False
            if immediate_check:
                # Reset flag and skip sleep to process immediately
                self.agent.set("immediate_cpu_check", False)
                await asyncio.sleep(0.01)  # Minimal delay to yield control
            else:
                await asyncio.sleep(1.0)  # Normal periodic check

    async def setup(self):
        """Agent setup hook: initialize state and attach behaviours.

        Sets default agent state keys, creates and registers the
        `FirewallBehaviour`, and starts the receive and resource behaviours.
        Initializes state variables for resource tracking, metrics, and threat status.
        """
        _log("NodeAgent", str(self.jid), "starting...")

        self.set("is_infected", False)
        self.set("node_dead", False)
        self.set("task_counter", 0)
        self.set("cpu_peak", 0.0)
        self.set("ddos_packets_received", 0)
        self.set("cpu_overload_ticks", 0)
        self.set("pings_answered", 0)
        self.set("base_cpu", self.get("base_cpu") or 10.0)
        self.set("base_bw", 5.0)
        self.set("active_tasks", {})
        self.set("self_isolated", False)

        # Insider threat state
        self.set("compromised", False)
        self.set("exfiltration_active", False)
        self.set("exfiltration_bandwidth", 0.0)
        self.set("infected_peers", set()) # Peers compromised by this node

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
    """CLI entrypoint to start a single `NodeAgent` instance for testing.

    Parses command-line arguments (jid, password, peers, heartbeat) and
    launches the SPADE agent. Exits cleanly on errors or KeyboardInterrupt.
    """
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