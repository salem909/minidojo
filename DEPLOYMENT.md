# 🚀 Deployment Checklist

This document provides a comprehensive checklist for deploying Mini-DOJO in various environments.

## ✅ Pre-Deployment Checklist

### System Requirements

- [ ] Docker Engine 20.10 or higher installed
- [ ] Docker Compose v2.0 or higher installed
- [ ] At least 2GB of available RAM
- [ ] At least 10GB of available disk space
- [ ] Ports 8080 and 30000-31000 available (or configured alternatives)

### Security Hardening (Production)

- [ ] Change `SECRET_KEY` in `docker-compose.yml` to a strong random value
- [ ] Change default database password (`POSTGRES_PASSWORD`)
- [ ] Set up a reverse proxy (nginx/Caddy) with HTTPS
- [ ] Enable firewall rules to restrict access to workspace ports
- [ ] Consider using Docker secrets instead of environment variables
- [ ] Implement rate limiting on the web service
- [ ] Upgrade password hashing from SHA256 to bcrypt/argon2
- [ ] Set up log aggregation and monitoring
- [ ] Configure automated backups for the PostgreSQL database

### Network Configuration

- [ ] If deploying remotely, update `HOST_PUBLIC` to your server's public IP or domain
- [ ] Ensure workspace ports (30000-31000) are accessible from users' browsers
- [ ] Configure DNS records if using a custom domain
- [ ] Set up SSL/TLS certificates (Let's Encrypt recommended)

## 📋 Deployment Steps

### Local Development

```bash
# 1. Build challenge image
cd mini-dojo/challenges/dojo1-ret2win/
docker build -t mini-dojo/dojo1-ret2win:latest .
cd ../../

# 2. Start services
docker compose up --build

# 3. Access at http://127.0.0.1:8080
```

### Production Server (Linux)

```bash
# 1. Clone repository
git clone <your-repo-url> mini-dojo
cd mini-dojo

# 2. Update configuration
nano docker-compose.yml  # Change SECRET_KEY, passwords, HOST_PUBLIC

# 3. Build challenge image
cd challenges/dojo1-ret2win/
docker build -t mini-dojo/dojo1-ret2win:latest .
cd ../../

# 4. Start in detached mode
docker compose up -d --build

# 5. Check logs
docker compose logs -f web

# 6. Verify services are running
docker compose ps
```

### Behind Nginx Reverse Proxy

Create `/etc/nginx/sites-available/mini-dojo`:

```nginx
server {
    listen 80;
    server_name dojo.example.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dojo.example.com;

    ssl_certificate /etc/letsencrypt/live/dojo.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dojo.example.com/privkey.pem;

    # Main web application
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Workspace terminals (WebSocket support)
    location ~ ^/workspace/(\d+)$ {
        proxy_pass http://127.0.0.1:$1;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Enable and restart:
```bash
sudo ln -s /etc/nginx/sites-available/mini-dojo /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

**Note**: You'll need to modify the web application to serve workspace URLs through the proxy (e.g., `https://dojo.example.com/workspace/30000` instead of `http://127.0.0.1:30000`).

### Docker Swarm / Kubernetes

For orchestrated deployments, you'll need to:

1. Convert `docker-compose.yml` to Swarm stack or Kubernetes manifests
2. Use a shared volume or external database for PostgreSQL
3. Implement a service mesh for container communication
4. Use an ingress controller for external access

This is beyond the scope of the MVP but can be added based on your infrastructure needs.

## 🔍 Post-Deployment Verification

### Health Checks

```bash
# Check all services are running
docker compose ps

# Check web service logs
docker compose logs web | tail -20

# Check database connectivity
docker compose exec db psql -U dojo -d dojo -c "SELECT COUNT(*) FROM challenges;"

# Check cleanup service
docker compose logs cleanup | tail -10
```

### Functional Tests

1. **Registration**: Create a new user account
2. **Login**: Log in with the created account
3. **Challenge List**: Verify "Dojo 1: ret2win" appears
4. **Start Workspace**: Click "Start Workspace" and verify container starts
5. **Terminal Access**: Click the workspace URL and verify terminal loads
6. **Exploit**: Run the exploit and verify you can get root shell
7. **Flag Submission**: Submit the flag and verify it's marked as solved
8. **Stop Workspace**: Click "Stop Workspace" and verify container is removed

### Performance Tests

```bash
# Check resource usage
docker stats

# Check database size
docker compose exec db psql -U dojo -d dojo -c "SELECT pg_size_pretty(pg_database_size('dojo'));"

# Check number of running workspace containers
docker ps --filter "name=dojo-" --format "table {{.Names}}\t{{.Status}}"
```

## 🛠️ Maintenance Tasks

### Regular Maintenance

- **Weekly**: Review cleanup service logs for errors
- **Weekly**: Check disk space usage (`df -h`)
- **Monthly**: Update Docker images (`docker compose pull`)
- **Monthly**: Backup database (`docker compose exec db pg_dump -U dojo dojo > backup.sql`)

### Backup Database

```bash
# Create backup
docker compose exec db pg_dump -U dojo dojo > backup_$(date +%Y%m%d).sql

# Restore from backup
cat backup_20260212.sql | docker compose exec -T db psql -U dojo dojo
```

### Update Challenge Images

```bash
# Rebuild challenge image
cd challenges/dojo1-ret2win/
docker build -t mini-dojo/dojo1-ret2win:latest .

# Restart web service to pick up new image
docker compose restart web
```

### Clean Up Old Containers

```bash
# Remove all stopped containers
docker container prune -f

# Remove unused images
docker image prune -a -f

# Remove unused volumes (CAUTION: This will delete database data if not in use)
docker volume prune -f
```

## 🐛 Troubleshooting

### Web Service Won't Start

```bash
# Check logs
docker compose logs web

# Common issues:
# - Database not ready: Wait 30 seconds and try again
# - Port 8080 in use: Change port in docker-compose.yml
# - Docker socket permission denied: Add user to docker group
```

### Workspace Containers Fail to Start

```bash
# Check Docker daemon
sudo systemctl status docker

# Check available resources
docker info | grep -E "CPUs|Total Memory"

# Check for port conflicts
netstat -tulpn | grep -E "3000[0-9]"

# Manually test challenge image
docker run --rm -it -p 7681:7681 -e FLAG="flag{test}" mini-dojo/dojo1-ret2win:latest
```

### Database Connection Errors

```bash
# Check database is running
docker compose ps db

# Check database logs
docker compose logs db

# Manually connect to database
docker compose exec db psql -U dojo -d dojo

# Reset database (CAUTION: Deletes all data)
docker compose down -v
docker compose up -d
```

### Cleanup Service Not Working

```bash
# Check cleanup service logs
docker compose logs cleanup

# Manually run cleanup
docker compose exec cleanup python cleanup.py

# Verify cleanup service has Docker socket access
docker compose exec cleanup docker ps
```

## 🔐 Security Best Practices

### Production Recommendations

1. **Use HTTPS**: Always use TLS/SSL in production
2. **Isolate Networks**: Create separate Docker networks for services
3. **Limit Docker Socket Access**: Consider using Docker socket proxy
4. **Implement Rate Limiting**: Prevent abuse of workspace creation
5. **Monitor Logs**: Set up centralized logging (ELK, Splunk, etc.)
6. **Regular Updates**: Keep Docker and base images up to date
7. **Backup Strategy**: Implement automated database backups
8. **Access Control**: Use firewall rules to restrict access
9. **Resource Quotas**: Set per-user workspace limits
10. **Audit Trail**: Log all user actions for security auditing

### Docker Security

```bash
# Run Docker daemon with user namespace remapping
# Edit /etc/docker/daemon.json:
{
  "userns-remap": "default"
}

# Restart Docker
sudo systemctl restart docker
```

## 📊 Monitoring

### Metrics to Track

- Number of active users
- Number of active workspaces
- Workspace creation/deletion rate
- Challenge solve rate
- Resource usage (CPU, memory, disk)
- Database size and query performance
- Container startup/failure rate

### Recommended Tools

- **Prometheus + Grafana**: Metrics and dashboards
- **ELK Stack**: Log aggregation and analysis
- **Portainer**: Docker container management UI
- **cAdvisor**: Container resource monitoring

---

**Need help?** Check the main [README.md](README.md) or open an issue on the project repository.
