# 📁 Project Structure

This document explains the organization and purpose of each file in the Mini-DOJO repository.

```
mini-dojo/
├── docker-compose.yml          # Orchestrates all services (web, db, cleanup)
├── README.md                   # Main documentation
├── QUICKSTART.md              # Quick start guide
├── STRUCTURE.md               # This file
│
├── web/                       # FastAPI web application
│   ├── Dockerfile             # Container definition for web service
│   ├── requirements.txt       # Python dependencies
│   ├── app.py                 # Main FastAPI application (routes, logic)
│   ├── db.py                  # Database connection and initialization
│   ├── models.py              # SQLAlchemy ORM models (User, Challenge, Workspace, Solve)
│   └── templates/             # Jinja2 HTML templates
│       ├── layout.html        # Base template with header/navigation
│       ├── login.html         # Login page
│       ├── register.html      # Registration page
│       ├── challenges.html    # Challenge list page
│       └── challenge.html     # Individual challenge detail page
│
├── cleanup/                   # Automated workspace cleanup service
│   ├── Dockerfile             # Container definition for cleanup service
│   ├── requirements.txt       # Python dependencies
│   └── cleanup.py             # Cleanup script (removes expired containers)
│
└── challenges/                # Challenge definitions
    └── dojo1-ret2win/         # First challenge: ret2win binary exploitation
        ├── Dockerfile         # Challenge container definition
        ├── entrypoint.sh      # Container startup script (creates flag, starts ttyd)
        ├── challenge.c        # Vulnerable C program source code
        └── README.md          # Challenge documentation
```

## Component Descriptions

### Root Level

- **docker-compose.yml**: Defines three services (`db`, `web`, `cleanup`) and their configuration. This is the entry point for starting the entire platform.
- **README.md**: Comprehensive documentation including features, setup instructions, and troubleshooting.

### Web Service (`web/`)

The web service is the core of the platform, handling user authentication, challenge management, and workspace orchestration.

#### Key Files:

- **app.py**: The FastAPI application containing all HTTP routes:
  - `/register`, `/login`, `/logout`: User authentication
  - `/challenges`: List all challenges
  - `/challenge/{id}`: View challenge details
  - `/challenge/{id}/start`: Start a workspace container
  - `/challenge/{id}/stop`: Stop a workspace container
  - `/challenge/{id}/submit`: Submit a flag for validation

- **models.py**: SQLAlchemy ORM models defining the database schema:
  - `User`: User accounts with password hashing
  - `Challenge`: Challenge definitions (slug, title, docker image)
  - `Workspace`: Active workspace containers (container ID, port, flag)
  - `Solve`: Tracks which users solved which challenges

- **db.py**: Database connection management and initialization. Seeds the database with the `dojo1-ret2win` challenge on startup.

- **templates/**: Jinja2 HTML templates for server-side rendering. All pages extend `layout.html` for consistent styling.

### Cleanup Service (`cleanup/`)

A background service that runs periodically to remove expired workspace containers.

- **cleanup.py**: 
  - Finds workspaces older than `WORKSPACE_TTL_HOURS`
  - Stops and removes their Docker containers
  - Marks workspaces as inactive in the database
  - Also removes orphaned containers not tracked in the database

### Challenges (`challenges/`)

Each challenge is a subdirectory containing its Docker image definition.

#### dojo1-ret2win:

- **challenge.c**: A simple C program with a buffer overflow vulnerability. Uses `gets()` to read user input without bounds checking. Contains a `win()` function that spawns a root shell when called.

- **Dockerfile**: 
  - Builds the challenge binary with disabled protections (`-fno-stack-protector`, `-z execstack`, `-no-pie`)
  - Sets SUID bit on the binary (`chmod 4755`)
  - Installs `ttyd` for the browser terminal
  - Creates the `hacker` user (uid 1000)

- **entrypoint.sh**: 
  - Creates `/flag` with the injected `FLAG` environment variable
  - Sets permissions to `0400` (readable only by root)
  - Starts `ttyd` on port 7681 as the `hacker` user

## Data Flow

### Starting a Workspace

1. User clicks "Start Workspace" on challenge page
2. `app.py` checks for existing active workspace (reuses if found)
3. Finds a free port in the configured range
4. Generates a unique flag: `flag{slug:user_id:random}`
5. Launches Docker container with:
   - Challenge image
   - `FLAG` environment variable
   - Port mapping (7681 → host port)
   - Resource limits (CPU, memory, PIDs)
6. Records workspace in database (container ID, port, flag hash)
7. Displays workspace URL to user

### Submitting a Flag

1. User submits flag via web form
2. `app.py` retrieves the workspace from database
3. Compares SHA256 hash of submitted flag with stored hash
4. If correct:
   - Creates a `Solve` record
   - Displays "Solved ✅" badge
5. If incorrect:
   - Shows error message

### Cleanup Process

1. Cleanup service runs every `CLEANUP_INTERVAL_SECONDS` (default: 300s)
2. Queries database for workspaces older than `WORKSPACE_TTL_HOURS`
3. For each expired workspace:
   - Stops the Docker container
   - Removes the container
   - Marks workspace as inactive
4. Also checks for orphaned containers (running but not in database)

## Security Considerations

### What's Protected

- **Docker socket isolation**: Only the `web` and `cleanup` services have access to `/var/run/docker.sock`. Workspace containers do NOT have this access.
- **Flag storage**: Flags are stored as SHA256 hashes in the database. The plaintext flag is only available inside the workspace container.
- **Session security**: User sessions use signed cookies with `itsdangerous`.
- **Resource limits**: Workspaces have CPU, memory, and PID limits to prevent resource exhaustion.

### What's NOT Protected (MVP Limitations)

- **Password storage**: Uses simple SHA256 hashing. Production should use bcrypt/argon2.
- **No rate limiting**: Users can start/stop workspaces rapidly.
- **No HTTPS**: The platform runs on HTTP. Production should use a reverse proxy with TLS.
- **Shared network**: All containers share the default Docker network.

## Extending the Platform

### Adding a New Challenge

1. Create a new directory in `challenges/`:
   ```bash
   mkdir challenges/my-challenge
   ```

2. Create a `Dockerfile` that:
   - Installs `ttyd`
   - Creates the challenge files
   - Sets up a SUID binary or other vulnerability
   - Includes an entrypoint that creates `/flag` from `$FLAG`

3. Build the image:
   ```bash
   docker build -t mini-dojo/my-challenge:latest challenges/my-challenge/
   ```

4. Add the challenge to the database by modifying `web/db.py` `init_db()`:
   ```python
   challenge = Challenge(
       slug="my-challenge",
       title="My Challenge Title",
       description="Description here",
       docker_image="mini-dojo/my-challenge:latest"
   )
   db.add(challenge)
   ```

5. Restart the web service to seed the new challenge.

### Customizing the UI

All HTML templates are in `web/templates/`. They use inline CSS for simplicity. You can:
- Modify colors and styling in `layout.html`
- Add new pages by creating new templates and routes in `app.py`
- Replace inline CSS with an external stylesheet

### Adjusting Resource Limits

Edit `web/app.py` in the `start_workspace()` function:
```python
container = docker_client.containers.run(
    # ...
    mem_limit="512m",      # Increase memory limit
    cpu_period=100000,
    cpu_quota=100000,      # Increase CPU quota (100% of 1 core)
    pids_limit=128,        # Increase process limit
)
```

## Database Schema

### Users
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| username | String | Unique username |
| password_hash | String | SHA256 hash of password |
| created_at | DateTime | Account creation timestamp |

### Challenges
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| slug | String | Unique identifier (e.g., "dojo1-ret2win") |
| title | String | Display name |
| description | String | Challenge description |
| docker_image | String | Docker image name |
| created_at | DateTime | Challenge creation timestamp |

### Workspaces
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | Foreign key to users |
| challenge_id | Integer | Foreign key to challenges |
| container_id | String | Docker container ID |
| host_port | Integer | Mapped host port for ttyd |
| flag | String | Plaintext flag (for this workspace) |
| flag_hash | String | SHA256 hash of flag |
| active | Boolean | Whether workspace is running |
| started_at | DateTime | Workspace start timestamp |

### Solves
| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | Foreign key to users |
| challenge_id | Integer | Foreign key to challenges |
| solved_at | DateTime | Solve timestamp |

---

This structure is designed to be simple, extensible, and educational. Feel free to modify it to suit your needs!
