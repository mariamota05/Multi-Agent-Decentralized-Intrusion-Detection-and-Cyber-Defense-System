# Pygame Visualization

## Installation

To enable the pygame visualization, install pygame:

```bash
pip install pygame
```

## Running with Visualization

```bash
python environment.py --time 30
```

The visualization window will show:
- **Routers** (large blue circles) - labeled R0, R1, R2, etc.
- **Nodes** (smaller green circles) - labeled N0.0, N0.1, etc.
- **Monitor** (gold circle) at the top
- **Connections** (gray lines between nodes and routers)
- **Router links** (thicker lines between routers)
- **Animated packets** (red dots) moving through the network

## Controls

- **ESC** or close window to stop
- Nodes show CPU usage percentage below them
- Node color intensity changes with CPU load (darker = more load)

## Disabling Visualization

Set `ENABLE_VISUALIZATION = False` in `environment.py` to run without pygame.

## Features

- Real-time packet animation
- Resource usage visualization (CPU/bandwidth)
- Network statistics panel (top-left corner)
- 60 FPS smooth animation
