# 🪟 Windows Setup Guide

This guide helps you run Mini-DOJO on Windows with Docker Desktop.

## Prerequisites

1. **Docker Desktop for Windows** installed and running
2. **WSL 2** enabled (recommended)
3. **PowerShell** or **Command Prompt**

## Step-by-Step Setup

### 1. Ensure Docker Desktop is Running

- Open Docker Desktop from the Start menu
- Wait for the status to show "Docker Desktop is running"
- Verify in PowerShell:
  ```powershell
  docker --version
  docker ps
  ```

### 2. Build the Challenge Image

```powershell
cd mini-dojo\challenges\dojo1-ret2win
docker build -t mini-dojo/dojo1-ret2win:latest .
```

**Expected output**: Build should complete successfully with "Successfully tagged mini-dojo/dojo1-ret2win:latest"

### 3. Return to Project Root

```powershell
cd ..\..
```

### 4. Start the Platform

```powershell
docker compose up --build
```

**Wait for these messages**:
```
✓ Database initialized
✓ Seeded challenge: dojo1-ret2win
Uvicorn running on http://0.0.0.0:8080
```

### 5. Access the Platform

Open your browser to: **http://127.0.0.1:8080**

## Common Windows Issues & Fixes

### ❌ Error: "Not supported URL scheme http+docker"

**Cause**: Docker Python SDK compatibility issue with Windows named pipes.

**Fix**: The updated code now handles this automatically. If you still see this error:

1. Stop the containers:
   ```powershell
   docker compose down
   ```

2. Rebuild with the updated code:
   ```powershell
   docker compose up --build
   ```

### ❌ Error: "The system cannot find the file specified"

**Cause**: Docker Desktop is not running.

**Fix**:
1. Launch Docker Desktop
2. Wait for it to fully start (green icon in system tray)
3. Try again

### ❌ Error: "access is denied" or "permission denied"

**Cause**: PowerShell execution policy or file permissions.

**Fix**:
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### ❌ Error: "WSL 2 installation is incomplete"

**Cause**: WSL 2 is not properly installed.

**Fix**:
```powershell
# Run as Administrator
wsl --install
wsl --set-default-version 2
# Restart your computer
```

### ❌ Error: Port 8080 already in use

**Cause**: Another application is using port 8080.

**Fix**: Edit `docker-compose.yml` and change the port:
```yaml
web:
  ports:
    - "9090:8080"  # Change 8080 to any free port
```

Then access at `http://127.0.0.1:9090`

### ❌ Workspace containers fail to start

**Cause**: Resource limits or Docker configuration.

**Fix**:
1. Open Docker Desktop settings
2. Go to **Resources**
3. Increase memory to at least 4GB
4. Increase CPUs to at least 2
5. Click "Apply & Restart"

## Windows-Specific Notes

### File Paths

Windows uses backslashes (`\`) for paths, but Docker uses forward slashes (`/`). The code handles this automatically, but if you need to manually specify paths:

```powershell
# Windows path
C:\Users\USER\Desktop\mini-dojo

# Docker path (inside containers)
/home/ubuntu/mini-dojo
```

### Line Endings

If you edit files on Windows, ensure they use Unix line endings (LF) not Windows (CRLF), especially for:
- `entrypoint.sh`
- Any shell scripts

**Fix in VS Code**:
- Click "CRLF" in the bottom-right status bar
- Select "LF"
- Save the file

### Docker Desktop Settings

Recommended settings for Mini-DOJO:

1. **General**:
   - ✅ Use WSL 2 based engine
   - ✅ Start Docker Desktop when you log in

2. **Resources**:
   - Memory: 4GB minimum
   - CPUs: 2 minimum
   - Disk: 20GB minimum

3. **Docker Engine** (advanced):
   ```json
   {
     "builder": {
       "gc": {
         "enabled": true,
         "defaultKeepStorage": "20GB"
       }
     }
   }
   ```

## Testing on Windows

### Quick Test

```powershell
# 1. Check Docker is running
docker ps

# 2. Check images are built
docker images | Select-String "mini-dojo"

# 3. Check services are running
docker compose ps

# 4. Test web service
curl http://127.0.0.1:8080/login
```

### Full Test

1. Register a user at http://127.0.0.1:8080/register
2. View challenges
3. Start a workspace
4. Open the terminal URL (should be http://127.0.0.1:30000 or similar)
5. Verify you can interact with the terminal
6. Submit a flag

## Stopping the Platform

```powershell
# Stop all services
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v
```

## Performance Tips

1. **Use WSL 2 backend**: Much faster than Hyper-V
2. **Store project in WSL**: If using WSL 2, store the project in the WSL filesystem (`\\wsl$\Ubuntu\home\...`)
3. **Disable antivirus scanning**: Add Docker Desktop and project folder to exclusions
4. **Close unused applications**: Free up RAM for Docker

## Troubleshooting Commands

```powershell
# View all logs
docker compose logs

# View specific service logs
docker compose logs web
docker compose logs db
docker compose logs cleanup

# Follow logs in real-time
docker compose logs -f web

# Check container status
docker compose ps

# Restart a specific service
docker compose restart web

# Rebuild a specific service
docker compose up -d --build web

# Clean up everything
docker compose down -v
docker system prune -a
```

## Getting Help

If you encounter issues not covered here:

1. Check Docker Desktop logs: Settings → Troubleshoot → View logs
2. Check service logs: `docker compose logs`
3. Verify Docker is healthy: `docker info`
4. Check Windows Event Viewer for system errors

## Alternative: Use the Demo

If you're having persistent issues with Docker on Windows, you can use the **simplified demo version** that doesn't require Docker:

See the demo at: https://8080-ib3upuvhls6d1jivloanw-65ff1222.sg1.manus.computer

This shows the exact same UI and functionality without needing Docker containers.

---

**Still having issues?** Make sure Docker Desktop is fully updated to the latest version and Windows is up to date.
