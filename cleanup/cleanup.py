#!/usr/bin/env python3
"""
Cleanup service for Mini-DOJO
Periodically removes workspace containers that exceed the TTL
"""

import os
import time
import docker
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dojo:dojo_pass@db:5432/dojo")
WORKSPACE_TTL_HOURS = int(os.getenv("WORKSPACE_TTL_HOURS", "6"))
CLEANUP_INTERVAL_SECONDS = int(os.getenv("CLEANUP_INTERVAL_SECONDS", "300"))  # 5 minutes

# Database setup
Base = declarative_base()


class Workspace(Base):
    __tablename__ = "workspaces"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    challenge_id = Column(Integer, nullable=False)
    container_id = Column(String, nullable=False)
    host_port = Column(Integer, nullable=False)
    flag = Column(String, nullable=False)
    flag_hash = Column(String, nullable=False)
    active = Column(Boolean, default=True)
    started_at = Column(DateTime, default=datetime.utcnow)


def get_docker_client():
    """Get Docker client with Windows compatibility"""
    try:
        client = docker.DockerClient(base_url='unix://var/run/docker.sock')
        client.ping()
        return client
    except Exception:
        try:
            client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
            client.ping()
            return client
        except Exception:
            return docker.from_env()


def cleanup_expired_workspaces():
    """Find and remove expired workspace containers"""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running cleanup...")
    
    # Connect to database
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    # Connect to Docker
    docker_client = get_docker_client()
    
    try:
        # Calculate expiration time
        expiration_time = datetime.utcnow() - timedelta(hours=WORKSPACE_TTL_HOURS)
        
        # Find expired active workspaces
        expired_workspaces = db.query(Workspace).filter(
            Workspace.active == True,
            Workspace.started_at < expiration_time
        ).all()
        
        if not expired_workspaces:
            print(f"  No expired workspaces found (TTL: {WORKSPACE_TTL_HOURS}h)")
            return
        
        print(f"  Found {len(expired_workspaces)} expired workspace(s)")
        
        for workspace in expired_workspaces:
            try:
                # Try to stop and remove the container
                container = docker_client.containers.get(workspace.container_id)
                container.stop(timeout=5)
                container.remove()
                print(f"  ✓ Removed container {workspace.container_id[:12]} (user_id={workspace.user_id}, age={datetime.utcnow() - workspace.started_at})")
            except docker.errors.NotFound:
                print(f"  ⚠ Container {workspace.container_id[:12]} not found (already removed)")
            except Exception as e:
                print(f"  ✗ Failed to remove container {workspace.container_id[:12]}: {e}")
            
            # Mark workspace as inactive
            workspace.active = False
        
        db.commit()
        print(f"  ✓ Marked {len(expired_workspaces)} workspace(s) as inactive")
        
    except Exception as e:
        print(f"  ✗ Cleanup error: {e}")
        db.rollback()
    finally:
        db.close()


def cleanup_orphaned_containers():
    """Remove containers that are running but not in database"""
    docker_client = get_docker_client()
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    try:
        # Get all active workspace container IDs from database
        active_container_ids = set(
            ws.container_id for ws in db.query(Workspace).filter_by(active=True).all()
        )
        
        # Find all running dojo containers
        containers = docker_client.containers.list(filters={"name": "dojo-"})
        
        orphaned_count = 0
        for container in containers:
            if container.id not in active_container_ids:
                try:
                    container.stop(timeout=5)
                    container.remove()
                    print(f"  ✓ Removed orphaned container {container.id[:12]} ({container.name})")
                    orphaned_count += 1
                except Exception as e:
                    print(f"  ✗ Failed to remove orphaned container {container.id[:12]}: {e}")
        
        if orphaned_count > 0:
            print(f"  ✓ Removed {orphaned_count} orphaned container(s)")
            
    except Exception as e:
        print(f"  ✗ Orphan cleanup error: {e}")
    finally:
        db.close()


def main():
    """Main cleanup loop"""
    print("=" * 60)
    print("Mini-DOJO Cleanup Service")
    print("=" * 60)
    print(f"Configuration:")
    print(f"  - Workspace TTL: {WORKSPACE_TTL_HOURS} hours")
    print(f"  - Cleanup interval: {CLEANUP_INTERVAL_SECONDS} seconds")
    print(f"  - Database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}")
    print("=" * 60)
    print()
    
    # Wait for database to be ready
    print("Waiting for database to be ready...")
    time.sleep(10)
    
    while True:
        try:
            cleanup_expired_workspaces()
            cleanup_orphaned_containers()
        except Exception as e:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Unexpected error: {e}")
        
        print(f"  Next cleanup in {CLEANUP_INTERVAL_SECONDS}s\n")
        time.sleep(CLEANUP_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
