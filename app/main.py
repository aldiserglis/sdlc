"""Login un reģistrācijas prototips (FastAPI + SQLite).

Mācību prototips ārpus pieteikumu plūsmas: nav daļa no docs/openapi.yaml.
Palaišana: uvicorn app.main:app --reload --port 8000
"""

import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

DB_PATH = Path(os.environ.get("AUTH_DB_PATH", Path(__file__).resolve().parent / "auth.db"))
SESSION_COOKIE = "session"
PBKDF2_ITERATIONS = 200_000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8

app = FastAPI(title="Login prototips", docs_url=None, redoc_url=None)


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, iterations, salt_hex, digest_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


async def read_form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    return {key: values[0] for key, values in parse_qs(body).items()}


def current_user(request: Request) -> sqlite3.Row | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with connect() as conn:
        return conn.execute(
            "SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id "
            "WHERE sessions.token = ?",
            (token,),
        ).fetchone()


BRAND = "Ezermala CRM"

STYLES = """
:root {
  --brand: #2563eb; --brand-dark: #1d4ed8; --ink: #101828; --text: #344054;
  --muted: #667085; --line: #d0d5dd; --soft-line: #eaecf0; --bg: #f8fafc;
  --danger: #b42318; --danger-bg: #fef3f2; --success: #067647; --success-bg: #ecfdf3;
}
* { box-sizing: border-box; }
body {
  margin: 0; color: var(--ink); background: var(--bg); -webkit-font-smoothing: antialiased;
  font-family: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
a { color: var(--brand); text-decoration: none; font-weight: 600; }
a:hover { text-decoration: underline; }

.logo { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 18px; }
.logo-mark {
  width: 32px; height: 32px; border-radius: 8px; display: grid; place-items: center;
  background: linear-gradient(135deg, #60a5fa, #2563eb); box-shadow: 0 4px 12px rgba(37,99,235,.35);
}

/* Pieteikšanās un reģistrācija */
.auth { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); min-height: 100vh; }
.auth-brand {
  color: #e4e9f7; padding: 48px 56px; display: flex; flex-direction: column; justify-content: space-between;
  background: radial-gradient(circle at 15% 0%, rgba(59,130,246,.45) 0, transparent 50%),
              linear-gradient(160deg, #0b1533 0%, #13235a 100%);
}
.auth-brand h2 {
  font-size: 36px; line-height: 1.2; color: #fff; margin: 0 0 16px; max-width: 28rem; letter-spacing: -0.02em;
}
.auth-brand .lead { color: #b6c2e2; font-size: 16px; line-height: 1.6; max-width: 28rem; margin: 0 0 32px; }
.features { list-style: none; padding: 0; margin: 0; display: grid; gap: 14px; }
.features li { display: flex; gap: 12px; align-items: center; font-size: 15px; }
.features svg { flex: none; }
.auth-brand footer { font-size: 13px; color: #8392bd; }
.auth-main { display: flex; align-items: center; justify-content: center; padding: 48px 24px; background: #fff; }
.auth-card { width: 100%; max-width: 400px; }
.auth-card > .logo { margin-bottom: 32px; display: none; }
.auth-card h1 { font-size: 28px; letter-spacing: -0.02em; margin: 0 0 8px; }
.subtitle { color: var(--muted); margin: 0 0 28px; font-size: 15px; }

.field { margin-bottom: 18px; }
.field label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; color: var(--text); }
.input-wrap { position: relative; }
.input-wrap .icon {
  position: absolute; left: 13px; top: 50%; transform: translateY(-50%); color: #98a2b3; pointer-events: none;
}
.input-wrap input {
  width: 100%; height: 44px; padding: 0 14px 0 40px; border: 1px solid var(--line); border-radius: 8px;
  font: inherit; font-size: 15px; color: var(--ink); background: #fff;
  box-shadow: 0 1px 2px rgba(16,24,40,.05); transition: border-color .15s, box-shadow .15s;
}
.input-wrap input::placeholder { color: #98a2b3; }
.input-wrap input:focus { outline: none; border-color: #84adff; box-shadow: 0 0 0 4px rgba(37,99,235,.15); }
.hint { font-size: 13px; color: var(--muted); margin-top: 6px; }

.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px; height: 44px; padding: 0 18px;
  border-radius: 8px; border: 1px solid var(--brand); background: var(--brand); color: #fff;
  font: inherit; font-weight: 600; font-size: 15px; cursor: pointer;
  box-shadow: 0 1px 2px rgba(16,24,40,.05); transition: background .15s;
}
.btn:hover { background: var(--brand-dark); }
.btn:focus-visible { outline: none; box-shadow: 0 0 0 4px rgba(37,99,235,.25); }
.btn-block { width: 100%; margin-top: 8px; }
.btn-secondary { background: #fff; color: var(--text); border-color: var(--line); height: 38px; font-size: 14px; }
.btn-secondary:hover { background: #f9fafb; }

.alert {
  display: flex; gap: 10px; align-items: flex-start; padding: 12px 14px; border-radius: 8px;
  font-size: 14px; margin-bottom: 20px; border: 1px solid;
}
.alert svg { flex: none; margin-top: 1px; }
.alert-error { background: var(--danger-bg); color: var(--danger); border-color: #fecdca; }
.alert-success { background: var(--success-bg); color: var(--success); border-color: #abefc6; }
.switch { text-align: center; margin-top: 24px; font-size: 14px; color: var(--muted); }
.secure-note {
  display: flex; align-items: center; justify-content: center; gap: 6px;
  margin-top: 40px; font-size: 12px; color: #98a2b3;
}

@media (max-width: 900px) {
  .auth { grid-template-columns: 1fr; }
  .auth-brand { display: none; }
  .auth-card > .logo { display: flex; }
}

/* Lietotnes čaula */
.topbar {
  height: 64px; background: #fff; border-bottom: 1px solid var(--soft-line);
  display: flex; align-items: center; justify-content: space-between; padding: 0 24px;
}
.user-menu { display: flex; align-items: center; gap: 12px; }
.avatar {
  width: 36px; height: 36px; border-radius: 50%; background: #dbeafe; color: var(--brand-dark);
  display: grid; place-items: center; font-weight: 700; font-size: 14px;
}
.user-email { font-size: 14px; color: var(--text); }
.content { max-width: 960px; margin: 0 auto; padding: 32px 24px; }
.content h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.02em; }
.panel {
  background: #fff; border: 1px solid var(--soft-line); border-radius: 12px;
  box-shadow: 0 1px 3px rgba(16,24,40,.06); margin-top: 24px;
}
.panel-header { padding: 18px 24px; border-bottom: 1px solid var(--soft-line); font-weight: 600; }
.details { margin: 0; padding: 4px 24px; }
.details div {
  display: grid; grid-template-columns: 200px 1fr; padding: 14px 0;
  border-bottom: 1px solid #f2f4f7; font-size: 14px;
}
.details div:last-child { border-bottom: 0; }
.details dt { color: var(--muted); }
.details dd { margin: 0; font-weight: 500; }
.badge {
  display: inline-flex; align-items: center; gap: 6px; padding: 2px 10px; border-radius: 999px;
  background: var(--success-bg); color: var(--success); font-size: 12px; font-weight: 600;
}
.badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #17b26a; }
@media (max-width: 600px) {
  .user-email { display: none; }
  .details div { grid-template-columns: 1fr; gap: 2px; }
}
"""

SVG_ATTRS = (
    'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"'
)
ICON_MAIL = (
    f'<svg class="icon" width="18" height="18" {SVG_ATTRS}>'
    '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/></svg>'
)
ICON_LOCK = (
    f'<svg class="icon" width="18" height="18" {SVG_ATTRS}>'
    '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
)
ICON_FEATURE = (
    f'<svg width="20" height="20" {SVG_ATTRS} style="color:#60a5fa">'
    '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/></svg>'
)
ICON_ERROR = (
    f'<svg width="18" height="18" {SVG_ATTRS}>'
    '<circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>'
)
ICON_SUCCESS = (
    f'<svg width="18" height="18" {SVG_ATTRS}>'
    '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/></svg>'
)
ICON_SHIELD = (
    f'<svg width="14" height="14" {SVG_ATTRS}>'
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
)
ICON_LOGOUT = (
    f'<svg width="16" height="16" {SVG_ATTRS}>'
    '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/>'
    '<path d="M21 12H9"/></svg>'
)
LOGO = (
    '<div class="logo"><span class="logo-mark">'
    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 17l6-6 4 4 8-8"/></svg>'
    f"</span>{BRAND}</div>"
)


def page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html lang="lv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · {BRAND}</title>
<style>{STYLES}</style>
</head>
<body>{body}</body>
</html>""",
        status_code=status_code,
    )


def alert(kind: str, message: str) -> str:
    if not message:
        return ""
    icon = ICON_ERROR if kind == "error" else ICON_SUCCESS
    return f'<div class="alert alert-{kind}" role="alert">{icon}<span>{html.escape(message)}</span></div>'


def field(name: str, label: str, input_html: str, icon: str, hint: str = "") -> str:
    hint_html = f'<p class="hint">{hint}</p>' if hint else ""
    return f"""<div class="field">
  <label for="{name}">{label}</label>
  <div class="input-wrap">{icon}{input_html}</div>{hint_html}
</div>"""


def auth_page(title: str, heading: str, subtitle: str, content: str, status_code: int):
    return page(
        title,
        f"""<div class="auth">
  <aside class="auth-brand">
    {LOGO}
    <div>
      <h2>Visas klientu attiecības vienuviet.</h2>
      <p class="lead">Pārvaldiet kontaktus, darījumus un saziņu vienotā, drošā darba vidē.</p>
      <ul class="features">
        <li>{ICON_FEATURE}Kontaktu un uzņēmumu pārvaldība</li>
        <li>{ICON_FEATURE}Darījumu plūsma un atskaites</li>
        <li>{ICON_FEATURE}Komandas sadarbība reāllaikā</li>
      </ul>
    </div>
    <footer>© 2026 {BRAND} · mācību prototips</footer>
  </aside>
  <main class="auth-main">
    <div class="auth-card">
      {LOGO}
      <h1>{heading}</h1>
      <p class="subtitle">{subtitle}</p>
      {content}
      <p class="secure-note">{ICON_SHIELD}Paroles tiek glabātas tikai kā drošs hešs</p>
    </div>
  </main>
</div>""",
        status_code,
    )


def login_form(error: str = "", notice: str = "", email: str = "", status_code: int = 200):
    return auth_page(
        "Pieteikšanās",
        "Laipni lūdzam atpakaļ",
        "Piesakieties savā kontā, lai turpinātu darbu.",
        f"""{alert("error", error)}{alert("success", notice)}
<form method="post" action="/login" novalidate>
  {field("email", "E-pasts", f'<input id="email" name="email" type="email" required autocomplete="email" autofocus placeholder="vards@uznemums.lv" value="{html.escape(email)}">', ICON_MAIL)}
  {field("password", "Parole", '<input id="password" name="password" type="password" required autocomplete="current-password" placeholder="••••••••">', ICON_LOCK)}
  <button class="btn btn-block" type="submit">Pieteikties</button>
</form>
<p class="switch">Nav konta? <a href="/register">Izveidot kontu</a></p>""",
        status_code,
    )


def register_form(error: str = "", email: str = "", status_code: int = 200):
    return auth_page(
        "Reģistrācija",
        "Izveidojiet kontu",
        "Aizpildiet datus, lai sāktu darbu.",
        f"""{alert("error", error)}
<form method="post" action="/register" novalidate>
  {field("email", "Darba e-pasts", f'<input id="email" name="email" type="email" required autocomplete="email" autofocus placeholder="vards@uznemums.lv" value="{html.escape(email)}">', ICON_MAIL)}
  {field("password", "Parole", f'<input id="password" name="password" type="password" required minlength="{MIN_PASSWORD_LENGTH}" autocomplete="new-password" placeholder="••••••••">', ICON_LOCK, f"Vismaz {MIN_PASSWORD_LENGTH} simboli.")}
  {field("password_confirm", "Apstipriniet paroli", '<input id="password_confirm" name="password_confirm" type="password" required autocomplete="new-password" placeholder="••••••••">', ICON_LOCK)}
  <button class="btn btn-block" type="submit">Izveidot kontu</button>
</form>
<p class="switch">Jau ir konts? <a href="/login">Pieteikties</a></p>""",
        status_code,
    )


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    email = html.escape(user["email"])
    return page(
        "Sākums",
        f"""<header class="topbar">
  {LOGO}
  <div class="user-menu">
    <span class="user-email">{email}</span>
    <span class="avatar">{html.escape(user["email"][0].upper())}</span>
    <form method="post" action="/logout">
      <button class="btn btn-secondary" type="submit">{ICON_LOGOUT}Iziet</button>
    </form>
  </div>
</header>
<main class="content">
  <h1>Sveiki!</h1>
  <p class="subtitle">Laipni lūdzam {BRAND}.</p>
  <section class="panel">
    <div class="panel-header">Konta informācija</div>
    <dl class="details">
      <div><dt>E-pasts</dt><dd>{email}</dd></div>
      <div><dt>Statuss</dt><dd><span class="badge">Aktīvs</span></dd></div>
      <div><dt>Reģistrēts</dt><dd>{html.escape(user["created_at"])} UTC</dd></div>
    </dl>
  </section>
</main>""",
    )


@app.get("/register", response_class=HTMLResponse)
def register_page():
    return register_form()


@app.post("/register", response_class=HTMLResponse)
async def register(request: Request):
    form = await read_form(request)
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")

    if not EMAIL_RE.match(email):
        return register_form("Nederīga e-pasta adrese.", email, 400)
    if len(password) < MIN_PASSWORD_LENGTH:
        return register_form(
            f"Parolei jābūt vismaz {MIN_PASSWORD_LENGTH} simbolus garai.", email, 400
        )
    if password != form.get("password_confirm", ""):
        return register_form("Paroles nesakrīt.", email, 400)

    try:
        with connect() as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, hash_password(password)),
            )
    except sqlite3.IntegrityError:
        return register_form("Lietotājs ar šo e-pastu jau eksistē.", email, 409)

    return login_form(notice="Reģistrācija veiksmīga. Piesakies.", email=email)


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return login_form()


@app.post("/login")
async def login(request: Request):
    form = await read_form(request)
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")

    with connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or not verify_password(password, user["password_hash"]):
            return login_form("Nepareizs e-pasts vai parole.", email=email, status_code=401)
        token = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user["id"]))

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
    return response


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response
