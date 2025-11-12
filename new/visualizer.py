"""Real-time pygame visualization for the SPADE network simulation.

This module provides a graphical interface to visualize:
- Routers and nodes positioned on a grid
- Network topology (connections between routers and nodes)
- Live message flow (animated packets)
- Agent resource usage (CPU/bandwidth via colors)

Usage:
    from visualizer import NetworkVisualizer
    
    viz = NetworkVisualizer(width=1200, height=800)
    viz.set_topology(routers, nodes, router_connections)
    
    # In your main loop:
    viz.update()
    viz.draw()
"""

import pygame
import sys
import math
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from collections import deque
import time


@dataclass
class Agent:
    """Represents an agent in the visualization."""
    name: str
    jid: str
    position: Tuple[int, int]
    agent_type: str  # 'router', 'node', 'monitor'
    cpu: float = 0.0
    bandwidth: float = 0.0
    is_active: bool = True


@dataclass
class Packet:
    """Represents a message packet moving through the network."""
    source: str
    destination: str
    current_pos: Tuple[float, float]
    target_pos: Tuple[float, float]
    color: Tuple[int, int, int]
    progress: float = 0.0
    speed: float = 2.0  # pixels per frame
    ttl: int = 64


class NetworkVisualizer:
    """Pygame-based network visualization."""
    
    # Colors
    BG_COLOR = (20, 20, 30)
    ROUTER_COLOR = (70, 130, 180)  # Steel blue
    NODE_COLOR = (60, 179, 113)     # Medium sea green
    MONITOR_COLOR = (255, 215, 0)   # Gold
    CONNECTION_COLOR = (60, 60, 80)
    TEXT_COLOR = (220, 220, 220)
    PACKET_COLOR = (255, 100, 100)
    
    def __init__(self, width: int = 1200, height: int = 800):
        """Initialize pygame visualization.
        
        Args:
            width: Window width in pixels
            height: Window height in pixels
        """
        pygame.init()
        self.width = width
        self.height = height
        self.screen = pygame.display.set_mode((width, height))
        pygame.display.set_caption("SPADE Network Simulator")
        
        self.clock = pygame.time.Clock()
        self.font_small = pygame.font.Font(None, 20)
        self.font_medium = pygame.font.Font(None, 28)
        self.font_large = pygame.font.Font(None, 36)
        
        # Network state
        self.agents: Dict[str, Agent] = {}
        self.connections: List[Tuple[str, str]] = []  # (agent1_jid, agent2_jid)
        self.router_connections: List[Tuple[str, str]] = []  # (router1_jid, router2_jid)
        self.packets: deque = deque(maxlen=50)  # Active packets
        
        # Stats
        self.total_messages = 0
        self.start_time = time.time()
        
    def set_topology(self, routers: List[Tuple], nodes: List[Tuple], 
                     router_topology: Dict[int, List[int]], domain: str = "localhost"):
        """Set up the network topology from environment data.
        
        Args:
            routers: List of (r_idx, router_jid, router_agent) tuples
            nodes: List of (r_idx, n_idx, node_jid, node_agent) tuples
            router_topology: Dict mapping router index to list of neighbor indices
            domain: XMPP domain
        """
        # Calculate positions (spread across screen)
        num_routers = len(routers)
        router_spacing = (self.width - 200) // max(num_routers, 1)
        
        # Add routers
        for r_idx, router_jid, _ in routers:
            name = f"R{r_idx}"
            x = 100 + r_idx * router_spacing
            y = self.height // 2
            self.agents[router_jid] = Agent(
                name=name,
                jid=router_jid,
                position=(x, y),
                agent_type='router'
            )
        
        # Add nodes around their parent routers
        nodes_per_router = {}
        for r_idx, n_idx, node_jid, _ in nodes:
            if r_idx not in nodes_per_router:
                nodes_per_router[r_idx] = []
            nodes_per_router[r_idx].append((n_idx, node_jid))
        
        for r_idx, node_list in nodes_per_router.items():
            router_jid = f"router{r_idx}@{domain}"
            if router_jid not in self.agents:
                continue
            
            router_pos = self.agents[router_jid].position
            num_nodes = len(node_list)
            
            # Position nodes in a circle around router
            for i, (n_idx, node_jid) in enumerate(node_list):
                angle = (i / num_nodes) * 2 * math.pi
                offset_x = int(120 * math.cos(angle))
                offset_y = int(120 * math.sin(angle))
                
                name = f"N{r_idx}.{n_idx}"
                self.agents[node_jid] = Agent(
                    name=name,
                    jid=node_jid,
                    position=(router_pos[0] + offset_x, router_pos[1] + offset_y),
                    agent_type='node'
                )
                
                # Add connection between node and router
                self.connections.append((node_jid, router_jid))
        
        # Add monitor (top center)
        monitor_jid = f"monitor@{domain}"
        self.agents[monitor_jid] = Agent(
            name="Monitor",
            jid=monitor_jid,
            position=(self.width // 2, 50),
            agent_type='monitor'
        )
        
        # Add router-to-router connections
        for r_idx, neighbors in router_topology.items():
            router_jid = f"router{r_idx}@{domain}"
            for neighbor_idx in neighbors:
                if r_idx < neighbor_idx:  # Avoid duplicate connections
                    neighbor_jid = f"router{neighbor_idx}@{domain}"
                    self.router_connections.append((router_jid, neighbor_jid))
    
    def add_packet(self, source_jid: str, dest_jid: str, ttl: int = 64):
        """Add an animated packet to visualize message flow.
        
        Args:
            source_jid: Source agent JID
            dest_jid: Destination agent JID
            ttl: Time to live
        """
        if source_jid not in self.agents or dest_jid not in self.agents:
            return
        
        source_pos = self.agents[source_jid].position
        dest_pos = self.agents[dest_jid].position
        
        packet = Packet(
            source=source_jid,
            destination=dest_jid,
            current_pos=source_pos,
            target_pos=dest_pos,
            color=self.PACKET_COLOR,
            ttl=ttl
        )
        self.packets.append(packet)
        self.total_messages += 1
    
    def update_agent_stats(self, jid: str, cpu: float = None, bandwidth: float = None):
        """Update agent resource statistics.
        
        Args:
            jid: Agent JID
            cpu: CPU usage percentage (0-100)
            bandwidth: Bandwidth usage percentage (0-100)
        """
        if jid in self.agents:
            if cpu is not None:
                self.agents[jid].cpu = cpu
            if bandwidth is not None:
                self.agents[jid].bandwidth = bandwidth
    
    def update(self):
        """Update simulation state (animate packets)."""
        # Update packet positions
        packets_to_remove = []
        for packet in self.packets:
            # Calculate direction vector
            dx = packet.target_pos[0] - packet.current_pos[0]
            dy = packet.target_pos[1] - packet.current_pos[1]
            distance = math.sqrt(dx**2 + dy**2)
            
            if distance < packet.speed:
                # Packet reached destination
                packets_to_remove.append(packet)
            else:
                # Move packet towards destination
                packet.current_pos = (
                    packet.current_pos[0] + (dx / distance) * packet.speed,
                    packet.current_pos[1] + (dy / distance) * packet.speed
                )
        
        # Remove arrived packets
        for packet in packets_to_remove:
            if packet in self.packets:
                self.packets.remove(packet)
    
    def draw(self):
        """Render the visualization."""
        self.screen.fill(self.BG_COLOR)
        
        # Draw connections (node-router and router-router)
        for conn in self.connections:
            if conn[0] in self.agents and conn[1] in self.agents:
                pos1 = self.agents[conn[0]].position
                pos2 = self.agents[conn[1]].position
                pygame.draw.line(self.screen, self.CONNECTION_COLOR, pos1, pos2, 1)
        
        # Draw router-router connections (thicker)
        for conn in self.router_connections:
            if conn[0] in self.agents and conn[1] in self.agents:
                pos1 = self.agents[conn[0]].position
                pos2 = self.agents[conn[1]].position
                pygame.draw.line(self.screen, (100, 100, 140), pos1, pos2, 2)
        
        # Draw agents
        for agent in self.agents.values():
            self._draw_agent(agent)
        
        # Draw packets
        for packet in self.packets:
            pygame.draw.circle(
                self.screen,
                packet.color,
                (int(packet.current_pos[0]), int(packet.current_pos[1])),
                5
            )
        
        # Draw stats panel
        self._draw_stats_panel()
        
        pygame.display.flip()
        self.clock.tick(60)  # 60 FPS
    
    def _draw_agent(self, agent: Agent):
        """Draw a single agent (router/node/monitor)."""
        x, y = agent.position
        
        # Choose size and color based on type
        if agent.agent_type == 'router':
            radius = 25
            color = self.ROUTER_COLOR
        elif agent.agent_type == 'monitor':
            radius = 20
            color = self.MONITOR_COLOR
        else:  # node
            radius = 15
            color = self.NODE_COLOR
        
        # Adjust color based on CPU usage (darker = higher usage)
        cpu_factor = min(agent.cpu / 100.0, 1.0)
        adjusted_color = tuple(int(c * (1 - cpu_factor * 0.5)) for c in color)
        
        # Draw circle
        pygame.draw.circle(self.screen, adjusted_color, (x, y), radius)
        pygame.draw.circle(self.screen, self.TEXT_COLOR, (x, y), radius, 2)
        
        # Draw label
        label = self.font_small.render(agent.name, True, self.TEXT_COLOR)
        label_rect = label.get_rect(center=(x, y - radius - 15))
        self.screen.blit(label, label_rect)
        
        # Draw CPU/BW if node
        if agent.agent_type == 'node' and (agent.cpu > 0 or agent.bandwidth > 0):
            stats_text = f"{agent.cpu:.0f}%"
            stats_label = self.font_small.render(stats_text, True, (200, 200, 100))
            stats_rect = stats_label.get_rect(center=(x, y + radius + 12))
            self.screen.blit(stats_label, stats_rect)
    
    def _draw_stats_panel(self):
        """Draw statistics panel."""
        runtime = int(time.time() - self.start_time)
        stats = [
            f"Runtime: {runtime}s",
            f"Messages: {self.total_messages}",
            f"Active Packets: {len(self.packets)}",
            f"Agents: {len(self.agents)}"
        ]
        
        y_offset = 10
        for stat in stats:
            text = self.font_small.render(stat, True, self.TEXT_COLOR)
            self.screen.blit(text, (10, y_offset))
            y_offset += 25
    
    def handle_events(self) -> bool:
        """Handle pygame events.
        
        Returns:
            False if user wants to quit, True otherwise
        """
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    return False
        return True
    
    def close(self):
        """Clean up pygame resources."""
        pygame.quit()
