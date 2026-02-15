from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from itsdangerous import URLSafeTimedSerializer
from contextlib import asynccontextmanager
import docker
import os
import secrets
import time
from datetime import datetime

from db import init_db, get_db
from models import User, Challenge, Workspace, Solve

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-in-production")
HOST_PUBLIC = os.getenv("HOST_PUBLIC", "127.0.0.1")
PORT_RANGE_START = int(os.getenv("PORT_RANGE_START", "30000"))
PORT_RANGE_END = int(os.getenv("PORT_RANGE_END", "31000"))
APP_ENV = os.getenv("APP_ENV", "development").lower()
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
CSRF_COOKIE_SECURE = os.getenv("CSRF_COOKIE_SECURE", str(SESSION_COOKIE_SECURE).lower()).lower() == "true"
CSRF_COOKIE_NAME = "csrf_token"
CSRF_MAX_AGE_SECONDS = 86400 * 7
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "10"))
login_attempts = {}

serializer = URLSafeTimedSerializer(SECRET_KEY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if APP_ENV == "production":
        if SECRET_KEY == "super-secret-key-change-in-production":
            raise RuntimeError("SECRET_KEY must be set in production")
        if not SESSION_COOKIE_SECURE:
            raise RuntimeError("SESSION_COOKIE_SECURE must be true in production")
        if not CSRF_COOKIE_SECURE:
            raise RuntimeError("CSRF_COOKIE_SECURE must be true in production")

    print("Initializing database...")
    init_db()
    print("✓ Database initialized")
    yield


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


def get_or_create_csrf_token(request: Request) -> str:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if token:
        return token
    return secrets.token_urlsafe(32)


def render_template(request: Request, template_name: str, context: dict):
    csrf_token = get_or_create_csrf_token(request)
    payload = {"request": request, "csrf_token": csrf_token, **context}
    response = templates.TemplateResponse(template_name, payload)
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        max_age=CSRF_MAX_AGE_SECONDS,
        samesite="lax",
        secure=CSRF_COOKIE_SECURE,
    )
    return response


def validate_csrf(request: Request, csrf_token: str):
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not csrf_cookie or not csrf_token:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    if not secrets.compare_digest(csrf_cookie, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def get_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def check_login_rate_limit(request: Request):
    ip_address = get_client_ip(request)
    now = int(time.time())
    record = login_attempts.get(ip_address)
    if not record:
        return

    if now - record["window_start"] > LOGIN_WINDOW_SECONDS:
        login_attempts.pop(ip_address, None)
        return

    if record["count"] >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")


def register_failed_login(request: Request):
    ip_address = get_client_ip(request)
    now = int(time.time())
    record = login_attempts.get(ip_address)

    if not record or now - record["window_start"] > LOGIN_WINDOW_SECONDS:
        login_attempts[ip_address] = {"count": 1, "window_start": now}
        return

    record["count"] += 1


def clear_login_attempts(request: Request):
    ip_address = get_client_ip(request)
    login_attempts.pop(ip_address, None)

# Initialize Docker client with explicit configuration for Windows compatibility
try:
    docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    # Test connection
    docker_client.ping()
except Exception:
    # Fallback for Windows (named pipe)
    try:
        docker_client = docker.DockerClient(base_url='npipe:////./pipe/docker_engine')
        docker_client.ping()
    except Exception:
        # Final fallback to from_env()
        docker_client = docker.from_env()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Get current logged-in user from session cookie"""
    token = request.cookies.get("session")
    if not token:
        return None
    
    try:
        user_id = serializer.loads(token, max_age=86400 * 7)  # 7 days
        user = db.query(User).filter_by(id=user_id).first()
        return user
    except:
        return None


def require_auth(request: Request, db: Session = Depends(get_db)):
    """Require authentication, redirect to login if not authenticated"""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def find_free_port(db: Session) -> int:
    """Find a free port in the configured range"""
    used_ports = set(
        ws.host_port for ws in db.query(Workspace).filter_by(active=True).all()
    )
    
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port not in used_ports:
            return port
    
    raise Exception("No free ports available in range")


def generate_flag(challenge_slug: str, user_id: int) -> str:
    """Generate a unique flag for a workspace"""
    random_part = secrets.token_hex(8)
    return f"flag{{{challenge_slug}:{user_id}:{random_part}}}"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db)):
    """Home page - redirect to challenges if logged in, otherwise to login"""
    user = get_current_user(request, db)
    if user:
        return RedirectResponse(url="/challenges", status_code=303)
    return RedirectResponse(url="/login", status_code=303)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page"""
    return render_template(request, "register.html", {})


@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle user registration"""
    validate_csrf(request, csrf_token)

    if len(password) < 8:
        return render_template(
            request,
            "register.html",
            {"error": "Password must be at least 8 characters long"}
        )

    # Check if username already exists
    existing = db.query(User).filter_by(username=username).first()
    if existing:
        return render_template(
            request,
            "register.html",
            {"error": "Username already exists"}
        )
    
    # Create new user
    user = User(username=username)
    user.set_password(password)
    db.add(user)
    db.commit()
    
    # Log in the user
    token = serializer.dumps(user.id)
    response = RedirectResponse(url="/challenges", status_code=303)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        max_age=86400 * 7,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE
    )
    return response


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    return render_template(request, "login.html", {})


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle user login"""
    validate_csrf(request, csrf_token)
    check_login_rate_limit(request)
    user = db.query(User).filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        register_failed_login(request)
        return render_template(
            request,
            "login.html",
            {"error": "Invalid username or password"}
        )

    clear_login_attempts(request)
    
    # Create session
    token = serializer.dumps(user.id)
    response = RedirectResponse(url="/challenges", status_code=303)
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        max_age=86400 * 7,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE
    )
    return response


@app.get("/logout")
async def logout():
    """Handle user logout"""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session")
    return response


@app.get("/challenges", response_class=HTMLResponse)
async def challenges_list(
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """List all challenges"""
    challenges = db.query(Challenge).all()
    
    # Get solve status for each challenge
    solved_ids = set(
        solve.challenge_id
        for solve in db.query(Solve).filter_by(user_id=user.id).all()
    )
    
    challenges_data = [
        {
            "id": c.id,
            "slug": c.slug,
            "title": c.title,
            "description": c.description,
            "solved": c.id in solved_ids
        }
        for c in challenges
    ]
    
    return render_template(
        request,
        "challenges.html",
        {"user": user, "challenges": challenges_data}
    )


@app.get("/leaderboard", response_class=HTMLResponse)
async def leaderboard(
    request: Request,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Leaderboard ranking users by total solves"""
    rows = (
        db.query(
            User.id,
            User.username,
            func.count(Solve.id).label("solve_count")
        )
        .outerjoin(Solve, Solve.user_id == User.id)
        .group_by(User.id, User.username)
        .order_by(func.count(Solve.id).desc(), User.username.asc())
        .all()
    )

    leaderboard_data = []
    for index, row in enumerate(rows, start=1):
        leaderboard_data.append(
            {
                "rank": index,
                "user_id": row.id,
                "username": row.username,
                "solve_count": row.solve_count,
                "is_current_user": row.id == user.id,
            }
        )

    return render_template(
        request,
        "leaderboard.html",
        {"user": user, "leaderboard": leaderboard_data}
    )


@app.get("/challenge/{challenge_id}", response_class=HTMLResponse)
async def challenge_detail(
    request: Request,
    challenge_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Challenge detail page"""
    challenge = db.query(Challenge).filter_by(id=challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Check if already solved
    solve = db.query(Solve).filter_by(
        user_id=user.id,
        challenge_id=challenge_id
    ).first()
    
    # Get active workspace if exists
    workspace = db.query(Workspace).filter_by(
        user_id=user.id,
        challenge_id=challenge_id,
        active=True
    ).first()
    
    workspace_url = None
    if workspace:
        workspace_url = f"http://{HOST_PUBLIC}:{workspace.host_port}"
    
    return render_template(
        request,
        "challenge.html",
        {
            "user": user,
            "challenge": challenge,
            "workspace": workspace,
            "workspace_url": workspace_url,
            "solved": solve is not None,
        }
    )


@app.post("/challenge/{challenge_id}/start")
async def start_workspace(
    request: Request,
    challenge_id: int,
    csrf_token: str = Form(...),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Start a workspace container for the challenge"""
    validate_csrf(request, csrf_token)
    challenge = db.query(Challenge).filter_by(id=challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Check if workspace already exists
    existing = db.query(Workspace).filter_by(
        user_id=user.id,
        challenge_id=challenge_id,
        active=True
    ).first()
    
    if existing:
        # Reuse existing workspace
        return RedirectResponse(
            url=f"/challenge/{challenge_id}",
            status_code=303
        )
    
    # Find free port
    host_port = find_free_port(db)
    
    # Generate flag
    flag = generate_flag(challenge.slug, user.id)
    
    # Start container
    try:
        container = docker_client.containers.run(
            challenge.docker_image,
            detach=True,
            environment={"FLAG": flag},
            ports={"7681/tcp": host_port},
            name=f"dojo-{user.id}-{challenge.slug}-{int(time.time())}",
            mem_limit="256m",
            cpu_period=100000,
            cpu_quota=50000,
            pids_limit=64,
            remove=False,
            auto_remove=False
        )
        
        # Record workspace in database
        workspace = Workspace(
            user_id=user.id,
            challenge_id=challenge_id,
            container_id=container.id,
            host_port=host_port,
            active=True
        )
        workspace.set_flag(flag)
        db.add(workspace)
        db.commit()
        
        print(f"✓ Started workspace for user {user.username} on port {host_port}")
        
    except Exception as e:
        print(f"✗ Failed to start workspace: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start workspace: {str(e)}")
    
    return RedirectResponse(
        url=f"/challenge/{challenge_id}",
        status_code=303
    )


@app.post("/challenge/{challenge_id}/stop")
async def stop_workspace(
    request: Request,
    challenge_id: int,
    csrf_token: str = Form(...),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Stop the workspace container"""
    validate_csrf(request, csrf_token)
    workspace = db.query(Workspace).filter_by(
        user_id=user.id,
        challenge_id=challenge_id,
        active=True
    ).first()
    
    if not workspace:
        return RedirectResponse(
            url=f"/challenge/{challenge_id}",
            status_code=303
        )
    
    # Stop and remove container
    try:
        container = docker_client.containers.get(workspace.container_id)
        container.stop(timeout=5)
        container.remove()
        print(f"✓ Stopped workspace container {workspace.container_id}")
    except docker.errors.NotFound:
        print(f"✗ Container {workspace.container_id} not found (already removed)")
    except Exception as e:
        print(f"✗ Failed to stop container: {e}")
    
    # Mark workspace as inactive
    workspace.active = False
    db.commit()
    
    return RedirectResponse(
        url=f"/challenge/{challenge_id}",
        status_code=303
    )


@app.post("/challenge/{challenge_id}/submit")
async def submit_flag(
    request: Request,
    challenge_id: int,
    flag: str = Form(...),
    csrf_token: str = Form(...),
    user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    """Submit a flag for validation"""
    validate_csrf(request, csrf_token)
    challenge = db.query(Challenge).filter_by(id=challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Get active workspace
    workspace = db.query(Workspace).filter_by(
        user_id=user.id,
        challenge_id=challenge_id,
        active=True
    ).first()
    
    if not workspace:
        return render_template(
            request,
            "challenge.html",
            {
                "user": user,
                "challenge": challenge,
                "workspace": None,
                "workspace_url": None,
                "solved": False,
                "error": "No active workspace. Please start a workspace first."
            },
        )
    
    # Validate flag
    if workspace.check_flag(flag.strip()):
        # Check if already solved
        existing_solve = db.query(Solve).filter_by(
            user_id=user.id,
            challenge_id=challenge_id
        ).first()
        
        if not existing_solve:
            solve = Solve(user_id=user.id, challenge_id=challenge_id)
            db.add(solve)
            db.commit()
            print(f"✓ User {user.username} solved {challenge.slug}")
        
        return RedirectResponse(
            url=f"/challenge/{challenge_id}",
            status_code=303
        )
    else:
        workspace_url = f"http://{HOST_PUBLIC}:{workspace.host_port}"
        return render_template(
            request,
            "challenge.html",
            {
                "user": user,
                "challenge": challenge,
                "workspace": workspace,
                "workspace_url": workspace_url,
                "solved": False,
                "error": "Incorrect flag. Try again!"
            },
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
