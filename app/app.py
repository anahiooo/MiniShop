"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import ast
import operator
import ipaddress
import logging
import os
import sqlite3
import subprocess
import requests
import uvicorn
import yaml
import html
import os
import secrets

from fastapi import Body, FastAPI, HTTPException, Request, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, ConfigDict
from pathlib import Path
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '../.env')
load_dotenv(dotenv_path=dotenv_path)

SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
AWS_KEY = os.environ["AWS_KEY"]
ALLOWED_FETCH_HOSTS = {"www.cyu.fr"}
LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "25/minute")

_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}

ROLE_PERMISSIONS = {
    "admin": {"user:list", "user:delete"},
    "user": set(),
}

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=False, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site="lax")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["X-Frame-Options"] = "DENY"
    return response

ph = PasswordHasher() 

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn



def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("unsupported expression")

def current_user(request: Request):
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="login required")
    row = db().execute(
        "SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="login required")
    return {
        "id": row["id"],
        "username": row["username"],
        "role": "admin" if row["is_admin"] else "user",
    }

def require(permission: str):
    def checker(user: dict = Depends(current_user)):
        if permission not in ROLE_PERMISSIONS.get(user["role"], set()):
            raise HTTPException(status_code=403, detail="forbidden")
        return user
    return checker

class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    email: str | None = None


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    log.error("Error %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse({"error": "internal server error"}, status_code=500)

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
@limiter.limit(LOGIN_RATE_LIMIT)
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]
    log.info(f"login attempt user={username}")
    sql = "SELECT * FROM users WHERE username=?" 
    row = db().execute(sql, (username,)).fetchone()

    try: 
        if not row:
            raise VerificationError()
        ph.verify(row["password"],password) 
    except (VerificationError, InvalidHashError):
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    
    request.session["user_id"] = row["id"]
    request.session["token"] = secrets.token_hex(32)
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    sql = "SELECT id, name, price FROM products WHERE name LIKE ?"
    return [dict(r) for r in db().execute(sql, (f"%{q}%",)).fetchall()]


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    try: 
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=422, detail="invalid IP address")
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "2", str(ip)],
            capture_output=True,
            text=True,
            timeout=5,
        ) 
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="ping timeout")
    return PlainTextResponse(out.stdout + out.stderr)


@app.get("/hello")
def hello(name: str = ""):
    return HTMLResponse(f"<h1>Bonjour {html.escape(name)}</h1>")


@app.get("/files/{name:path}")
def get_file(name: str):
    base = Path(UPLOAD_DIR).resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base) or not target.is_file():
        raise HTTPException(status_code=404, detail="not_found")
    return FileResponse(target)


@app.post("/calc")
def calc(data: dict = Body(...)):
    expr = data.get("expr")
    if not isinstance(expr, str) or len(expr) > 100:
        raise HTTPException(status_code=422, detail="invalid expression")
    try:
        result = _safe_eval(ast.parse(expr, mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError, RecursionError):
        raise HTTPException(status_code=400, detail="invalid expression")
    return {"result": str(result)}


@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        cfg = yaml.safe_load(await request.body())
    except yaml.YAMLError:
        raise HTTPException(status_code=400, detail="invalid YAML")
    
    return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}


@app.post("/import-profile")
async def import_profile(profile: Profile):
    return {"profile": str(profile)}


@app.get("/fetch")
def fetch(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        raise HTTPException(status_code=400, detail="url not allowed")
    try: 
        r = requests.get(url, timeout=5, verify=True, allow_redirects=False,)
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="upstream error")
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user: dict = Depends(current_user)):
    row = db().execute("SELECT * FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, user["id"],)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@app.get("/admin/users")
def admin_users(user: dict = Depends(require("user:list"))):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, user: dict = Depends(require("user:delete"))):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="127.0.0.1", port=5000)
