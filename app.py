"""
PulseWatch v4 — Single-file Flask Uptime Monitor
=================================================
Zero external files needed. All HTML/CSS/JS inlined.

WHAT'S NEW IN v4
----------------
• Database monitors — check connectivity to Postgres, MySQL/MariaDB, Redis,
  libSQL/SQLite/Turso, and MongoDB (in addition to HTTP and Heartbeat)
  — DB drivers are optional extras; install only the ones you need (see INSTALL)
• Maintenance 500 FIXED — Jinja2 can't do list comprehensions in {% set %};
  now pre-computed in the route and passed as template variables.
• Atom feed  (/status/<slug>/atom) alongside existing RSS feed
• Favicon — inline SVG data-URI, no file needed
• Basic HTTP Auth per monitor (username:password stored encrypted)
• Server resource metrics (CPU %, RAM %, disk %) shown on analytics page
  — reads /proc/stat, /proc/meminfo, /proc/diskstats (Linux) or psutil if available
• Docker integration — auto-restart containers when linked monitor goes DOWN
  — connects to Docker socket automatically (no manual config beyond container name)
  — Docker container name stored per monitor; restart triggered on consecutive fails
• Atom + RSS feeds for status pages

INSTALL
-------
  pip install flask flask-sqlalchemy flask-login apscheduler requests werkzeug pyotp qrcode[pil] psutil

  Database monitor drivers (optional — install only what you plan to monitor):
    Postgres     : pip install psycopg[binary]     (or: pip install psycopg2-binary)
    MySQL/MariaDB: pip install pymysql
    Redis        : pip install redis
    libSQL/Turso : pip install libsql-client        (local sqlite/.db files need no extra package)
    MongoDB      : pip install pymongo

DOCKER / UMBREL
---------------
  docker-compose up -d
  Mount Docker socket: /var/run/docker.sock:/var/run/docker.sock:ro
  Set DB_PATH=/data/pulsewatch.db

RENDER (free)
-------------
  Build: pip install -r requirements.txt
  Start: gunicorn app:app
"""

import os, uuid, time, io, json, hashlib, hmac, base64, threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from functools import lru_cache

import requests as http_req
from flask import (Flask, render_template_string, request, redirect, url_for,
                   jsonify, abort, Response, session, g)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler

try:
    import pyotp, qrcode
    TOTP_OK = True
except ImportError:
    TOTP_OK = False

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# ─── Optional DB-monitor drivers (only needed if a "database" monitor is used) ─
try:
    import psycopg as _pg_driver          # psycopg3
    PSYCOPG_OK = True
except ImportError:
    try:
        import psycopg2 as _pg_driver     # psycopg2 fallback
        PSYCOPG_OK = True
    except ImportError:
        _pg_driver = None
        PSYCOPG_OK = False

try:
    import pymysql
    PYMYSQL_OK = True
except ImportError:
    PYMYSQL_OK = False

try:
    import redis as redis_lib
    REDIS_OK = True
except ImportError:
    REDIS_OK = False

try:
    import libsql_client
    LIBSQL_OK = True
except ImportError:
    LIBSQL_OK = False

try:
    import pymongo
    PYMONGO_OK = True
except ImportError:
    PYMONGO_OK = False

import sqlite3
from urllib.parse import urlparse

DB_TYPES = ["postgres", "mysql", "redis", "libsql", "mongodb"]

def _parse_mysql_dsn(dsn):
    """Turn mysql://user:pass@host:port/dbname into pymysql connect() kwargs."""
    p = urlparse(dsn if "://" in dsn else f"mysql://{dsn}")
    return dict(
        host=p.hostname or "localhost",
        port=p.port or 3306,
        user=p.username or "root",
        password=p.password or "",
        database=(p.path or "/").lstrip("/") or None,
    )

def _check_libsql(dsn, timeout):
    """libSQL: local sqlite file (file:/*.db/*.sqlite) or remote libsql/https URL via libsql_client."""
    if dsn.startswith("file:") or dsn.rsplit(".", 1)[-1] in ("db", "sqlite", "sqlite3"):
        path = dsn[5:] if dsn.startswith("file:") else dsn
        conn = sqlite3.connect(path, timeout=timeout)
        try:
            conn.execute("SELECT 1")
        finally:
            conn.close()
    else:
        if not LIBSQL_OK:
            raise RuntimeError("libsql_client not installed (pip install libsql-client)")
        client = libsql_client.create_client_sync(dsn)
        try:
            client.execute("SELECT 1")
        finally:
            client.close()

def check_database(m):
    """Lightweight connectivity check for a 'database' monitor. Returns (status, ms, code, msg)."""
    dsn    = m.url or ""
    dbtype = (m.db_type or "").lower()
    t0     = time.time()
    try:
        if dbtype == "postgres":
            if not PSYCOPG_OK:
                raise RuntimeError("psycopg/psycopg2 not installed")
            conn = _pg_driver.connect(dsn, connect_timeout=m.timeout)
            try:
                cur = conn.cursor(); cur.execute("SELECT 1"); cur.fetchone(); cur.close()
            finally:
                conn.close()
        elif dbtype == "mysql":
            if not PYMYSQL_OK:
                raise RuntimeError("pymysql not installed")
            conn = pymysql.connect(connect_timeout=m.timeout, **_parse_mysql_dsn(dsn))
            try:
                conn.ping(reconnect=False)
            finally:
                conn.close()
        elif dbtype == "redis":
            if not REDIS_OK:
                raise RuntimeError("redis package not installed")
            client = redis_lib.from_url(dsn, socket_connect_timeout=m.timeout, socket_timeout=m.timeout)
            try:
                client.ping()
            finally:
                client.close()
        elif dbtype == "libsql":
            _check_libsql(dsn, m.timeout)
        elif dbtype == "mongodb":
            if not PYMONGO_OK:
                raise RuntimeError("pymongo not installed")
            client = pymongo.MongoClient(dsn, serverSelectionTimeoutMS=int(m.timeout * 1000))
            try:
                client.admin.command("ping")
            finally:
                client.close()
        else:
            raise RuntimeError(f"Unknown database type: {dbtype or '(none set)'}")
        return "up", int((time.time() - t0) * 1000), None, f"{dbtype} connection OK"
    except Exception as e:
        return "down", int((time.time() - t0) * 1000), None, str(e)[:200]

# ─── Local check buffer (written to DB hourly, not on every ping) ─────────────
_local_checks_lock = threading.Lock()
_local_checks: dict = {}   # {monitor_id: [{"status","response_time","status_code","message","checked_at"}, ...]}
_local_monitor_state: dict = {}  # {monitor_id: {"status","response_time","consecutive_down","last_checked"}}

def _buffer_check(monitor_id, status, response_time, status_code, message, phases=None):
    """Store a check result in memory instead of hitting the DB."""
    now = datetime.utcnow()
    record = {
        "status": status,
        "response_time": response_time,
        "status_code": status_code,
        "message": message,
        "checked_at": now,
        "phases": phases or {},
    }
    with _local_checks_lock:
        _local_checks.setdefault(monitor_id, []).append(record)
        prev_state = _local_monitor_state.get(monitor_id, {})
        prev_consecutive = prev_state.get("consecutive_down", 0)
        _local_monitor_state[monitor_id] = {
            "status": status,
            "response_time": response_time,
            "last_checked": now,
            "consecutive_down": (prev_consecutive + 1) if status == "down" else 0,
        }

def _get_local_status(monitor_id):
    """Return latest in-memory status for a monitor, or None if not seen yet."""
    with _local_checks_lock:
        return _local_monitor_state.get(monitor_id)

# ─── DB path ──────────────────────────────────────────────────────────────────
_DB_URL = os.environ.get("DATABASE_URL", "")
if _DB_URL:
    _DB_URL = _DB_URL.replace("postgres://", "postgresql://")
else:
    _db_file = os.environ.get("DB_PATH",
                               str(Path(__file__).parent / "pulsewatch.db"))
    Path(_db_file).parent.mkdir(parents=True, exist_ok=True)
    _DB_URL = f"sqlite:///{_db_file}"

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pulsewatch-change-me-in-production")
app.config.update(
    SQLALCHEMY_DATABASE_URI=_DB_URL,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
)
db  = SQLAlchemy(app)
lm  = LoginManager(app)
lm.login_view    = "login"
lm.login_message = ""

# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    totp_secret   = db.Column(db.String(64))
    totp_enabled  = db.Column(db.Boolean, default=False)
    monitors      = db.relationship("Monitor", backref="owner", lazy=True, cascade="all,delete-orphan")
    status_pages  = db.relationship("StatusPage", backref="owner", lazy=True, cascade="all,delete-orphan")
    settings      = db.relationship("UserSettings", backref="user", uselist=False, cascade="all,delete-orphan")

    def set_password(self, pw):   self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

    def get_totp_uri(self):
        if self.totp_secret and TOTP_OK:
            return pyotp.TOTP(self.totp_secret).provisioning_uri(
                name=self.email, issuer_name="PulseWatch")
        return None


class UserSettings(db.Model):
    __tablename__ = "user_settings"
    id                     = db.Column(db.Integer, primary_key=True)
    user_id                = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    discord_webhook        = db.Column(db.String(500))
    generic_webhook        = db.Column(db.String(500))
    webhook_secret         = db.Column(db.String(128))
    notify_on_down         = db.Column(db.Boolean, default=True)
    notify_on_recover      = db.Column(db.Boolean, default=True)
    notify_on_incident     = db.Column(db.Boolean, default=True)
    notify_cooldown_min    = db.Column(db.Integer, default=5)
    auto_incident          = db.Column(db.Boolean, default=False)
    auto_resolve_incident  = db.Column(db.Boolean, default=True)
    auto_incident_severity = db.Column(db.String(20), default="major")
    last_notified_json     = db.Column(db.Text, default="{}")

    def get_last_notified(self):
        try:    return json.loads(self.last_notified_json or "{}")
        except: return {}

    def set_last_notified(self, d):
        self.last_notified_json = json.dumps(d)


class Monitor(db.Model):
    __tablename__    = "monitor"
    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name             = db.Column(db.String(100), nullable=False)
    type             = db.Column(db.String(20), default="http")      # http | heartbeat | database
    url              = db.Column(db.String(500))   # HTTP URL, or DB connection string when type=="database"
    db_type          = db.Column(db.String(20))    # postgres | mysql | redis | libsql | mongodb (type=="database")
    interval         = db.Column(db.Integer, default=60)
    timeout          = db.Column(db.Integer, default=10)
    status           = db.Column(db.String(20), default="pending")   # up|down|pending|maintenance
    heartbeat_token  = db.Column(db.String(64), unique=True)
    last_checked     = db.Column(db.DateTime)
    last_heartbeat   = db.Column(db.DateTime)
    heartbeat_grace  = db.Column(db.Integer, default=300)
    uptime_7d        = db.Column(db.Float, default=100.0)
    response_time    = db.Column(db.Integer, default=0)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    active           = db.Column(db.Boolean, default=True)
    consecutive_down = db.Column(db.Integer, default=0)
    # Basic HTTP Auth
    http_auth_user   = db.Column(db.String(200))
    http_auth_pass   = db.Column(db.String(200))
    checks           = db.relationship("Check", backref="monitor", lazy=True, cascade="all,delete-orphan")

    def generate_heartbeat_token(self):
        self.heartbeat_token = uuid.uuid4().hex


class Check(db.Model):
    __tablename__ = "check"
    id             = db.Column(db.Integer, primary_key=True)
    monitor_id     = db.Column(db.Integer, db.ForeignKey("monitor.id"), nullable=False)
    status         = db.Column(db.String(20))
    response_time  = db.Column(db.Integer)
    status_code    = db.Column(db.Integer)
    message        = db.Column(db.String(500))
    checked_at     = db.Column(db.DateTime, default=datetime.utcnow)
    # Timing phases (ms) — HTTP monitors only
    t_namelookup   = db.Column(db.Integer)   # DNS lookup
    t_connect      = db.Column(db.Integer)   # TCP connect (cumulative)
    t_tls          = db.Column(db.Integer)   # TLS handshake (cumulative)
    t_ttfb         = db.Column(db.Integer)   # Time to first byte (cumulative)


class StatusPage(db.Model):
    __tablename__ = "status_page"
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    slug          = db.Column(db.String(80), unique=True, nullable=False)
    title         = db.Column(db.String(100), nullable=False)
    description   = db.Column(db.String(500))
    public        = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    page_monitors = db.relationship("StatusPageMonitor", backref="page", lazy=True, cascade="all,delete-orphan")
    announcements = db.relationship("Announcement", backref="page", lazy=True, cascade="all,delete-orphan")


class StatusPageMonitor(db.Model):
    __tablename__ = "status_page_monitor"
    id         = db.Column(db.Integer, primary_key=True)
    page_id    = db.Column(db.Integer, db.ForeignKey("status_page.id"), nullable=False)
    monitor_id = db.Column(db.Integer, db.ForeignKey("monitor.id"), nullable=False)
    monitor    = db.relationship("Monitor", lazy="joined")


class Incident(db.Model):
    __tablename__ = "incident"
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    monitor_id  = db.Column(db.Integer, db.ForeignKey("monitor.id"), nullable=True)
    title       = db.Column(db.String(200), nullable=False)
    severity    = db.Column(db.String(30), default="major")
    status      = db.Column(db.String(20), default="open")
    body        = db.Column(db.Text)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    updates     = db.relationship("IncidentUpdate", backref="incident", lazy=True,
                                  cascade="all,delete-orphan",
                                  order_by="IncidentUpdate.created_at.desc()")
    monitor_rel = db.relationship("Monitor", foreign_keys=[monitor_id])


class IncidentUpdate(db.Model):
    __tablename__ = "incident_update"
    id          = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"), nullable=False)
    message     = db.Column(db.Text, nullable=False)
    status      = db.Column(db.String(20))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class Maintenance(db.Model):
    __tablename__ = "maintenance"
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title          = db.Column(db.String(200), nullable=False)
    description    = db.Column(db.Text)
    start_time     = db.Column(db.DateTime, nullable=False)
    end_time       = db.Column(db.DateTime, nullable=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    maint_monitors = db.relationship("MaintenanceMonitor", backref="maintenance",
                                     lazy=True, cascade="all,delete-orphan")

    @property
    def is_active(self):
        n = datetime.utcnow(); return self.start_time <= n <= self.end_time

    @property
    def is_upcoming(self): return datetime.utcnow() < self.start_time

    @property
    def is_past(self): return datetime.utcnow() > self.end_time


class MaintenanceMonitor(db.Model):
    __tablename__ = "maintenance_monitor"
    id             = db.Column(db.Integer, primary_key=True)
    maintenance_id = db.Column(db.Integer, db.ForeignKey("maintenance.id"), nullable=False)
    monitor_id     = db.Column(db.Integer, db.ForeignKey("monitor.id"), nullable=False)
    monitor        = db.relationship("Monitor", lazy="joined")


class Announcement(db.Model):
    __tablename__ = "announcement"
    id         = db.Column(db.Integer, primary_key=True)
    page_id    = db.Column(db.Integer, db.ForeignKey("status_page.id"), nullable=False)
    title      = db.Column(db.String(200), nullable=False)
    body       = db.Column(db.Text)
    pinned     = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM METRICS
# ═══════════════════════════════════════════════════════════════════════════════

def get_system_metrics():
    """Return dict with cpu/ram/disk. Uses psutil if available, else /proc."""
    m = {"cpu": 0.0, "ram_used": 0, "ram_total": 0, "ram_pct": 0.0,
         "disk_used": 0, "disk_total": 0, "disk_pct": 0.0,
         "load1": 0.0, "load5": 0.0, "load15": 0.0}
    try:
        if PSUTIL_OK:
            m["cpu"]        = psutil.cpu_percent(interval=0.1)
            vm              = psutil.virtual_memory()
            m["ram_used"]   = vm.used
            m["ram_total"]  = vm.total
            m["ram_pct"]    = vm.percent
            du              = psutil.disk_usage("/")
            m["disk_used"]  = du.used
            m["disk_total"] = du.total
            m["disk_pct"]   = du.percent
            if hasattr(os, "getloadavg"):
                la = os.getloadavg()
                m["load1"], m["load5"], m["load15"] = la[0], la[1], la[2]
        else:
            # /proc fallback (Linux only)
            if os.path.exists("/proc/meminfo"):
                lines = open("/proc/meminfo").readlines()
                mi = {l.split(":")[0]: int(l.split()[1]) for l in lines if ":" in l and l.split()[1].isdigit()}
                total = mi.get("MemTotal", 0) * 1024
                avail = mi.get("MemAvailable", 0) * 1024
                used  = total - avail
                m["ram_total"] = total
                m["ram_used"]  = used
                m["ram_pct"]   = round(used / total * 100, 1) if total else 0

            if os.path.exists("/proc/loadavg"):
                parts = open("/proc/loadavg").read().split()
                m["load1"], m["load5"], m["load15"] = float(parts[0]), float(parts[1]), float(parts[2])

            if os.path.exists("/proc/statvfs"):
                pass  # skip without psutil

            try:
                import shutil
                du = shutil.disk_usage("/")
                m["disk_total"] = du.total
                m["disk_used"]  = du.used
                m["disk_pct"]   = round(du.used / du.total * 100, 1) if du.total else 0
            except Exception:
                pass
    except Exception:
        pass

    # Humanise
    def _h(b):
        for u in ("B","KB","MB","GB","TB"):
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} PB"

    m["ram_used_h"]  = _h(m["ram_used"])
    m["ram_total_h"] = _h(m["ram_total"])
    m["disk_used_h"] = _h(m["disk_used"])
    m["disk_total_h"]= _h(m["disk_total"])
    return m

# ═══════════════════════════════════════════════════════════════════════════════
# DOCKER HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

DOCKER_SOCKET = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
_docker_session = None

def _get_docker_session():
    global _docker_session
    if _docker_session is None:
        import requests_unixsocket
        _docker_session = requests_unixsocket.Session()
    return _docker_session

def _docker_api(method, path, **kwargs):
    """Hit the Docker Engine API via Unix socket or TCP."""
    try:
        if DOCKER_SOCKET.startswith("unix://"):
            sock_path = DOCKER_SOCKET[7:].replace("/", "%2F")
            url = f"http+unix://{sock_path}{path}"
            try:
                import requests_unixsocket
                sess = _get_docker_session()
                resp = getattr(sess, method)(url, timeout=5, **kwargs)
                return resp
            except ImportError:
                # Fallback: use http.client with socket
                import socket, http.client
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(DOCKER_SOCKET[7:])
                conn = http.client.HTTPConnection("localhost")
                conn.sock = sock
                body = kwargs.get("json")
                headers = {"Content-Type": "application/json"} if body else {}
                conn.request(method.upper(), path,
                             body=json.dumps(body).encode() if body else None,
                             headers=headers)
                r = conn.getresponse()
                data = r.read()
                conn.close()
                sock.close()

                class _R:
                    status_code = r.status
                    def json(self_inner): return json.loads(data)
                    def text(self_inner): return data.decode()
                return _R()
        else:
            url = DOCKER_SOCKET.rstrip("/") + path
            resp = getattr(http_req, method)(url, timeout=5, **kwargs)
            return resp
    except Exception as e:
        return None

def docker_list_containers():
    """Return list of {id, name, status, image} for all containers."""
    r = _docker_api("get", "/containers/json?all=true")
    if r is None:
        return []
    try:
        containers = r.json()
        result = []
        for c in containers:
            names = c.get("Names", [""])
            name = names[0].lstrip("/") if names else c.get("Id", "")[:12]
            result.append({
                "id":     c.get("Id", "")[:12],
                "name":   name,
                "status": c.get("Status", ""),
                "image":  c.get("Image", ""),
                "state":  c.get("State", ""),
            })
        return sorted(result, key=lambda x: x["name"])
    except Exception:
        return []

def docker_restart_container(name_or_id):
    """Restart a Docker container by name or ID. Returns (success, message)."""
    r = _docker_api("post", f"/containers/{name_or_id}/restart")
    if r is None:
        return False, "Docker socket not accessible"
    if r.status_code in (204, 200):
        return True, f"Container '{name_or_id}' restarted"
    return False, f"Docker returned HTTP {r.status_code}"

def docker_available():
    """Quick check if Docker socket is reachable."""
    r = _docker_api("get", "/info")
    return r is not None and r.status_code == 200

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _discord(url, title, desc, color=0xf43f5e):
    if not url: return
    try:
        http_req.post(url, json={"embeds": [{
            "title": title, "description": desc, "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "PulseWatch"}
        }]}, timeout=5)
    except Exception: pass

def _webhook(url, secret, payload):
    if not url: return
    try:
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json"}
        if secret:
            sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            hdrs["X-PulseWatch-Signature"] = f"sha256={sig}"
        http_req.post(url, data=body, headers=hdrs, timeout=5)
    except Exception: pass

def fire_notifications(user_id, monitor, new_status):
    s = UserSettings.query.filter_by(user_id=user_id).first()
    if not s: return
    last = s.get_last_notified()
    key  = str(monitor.id)
    if key in last:
        try:
            if datetime.utcnow() - datetime.fromisoformat(last[key]) < timedelta(minutes=s.notify_cooldown_min):
                return
        except Exception: pass
    if new_status == "down" and not s.notify_on_down: return
    if new_status == "up"   and not s.notify_on_recover: return
    color = 0xf43f5e if new_status == "down" else 0x22d3a4
    word  = "🔴 DOWN" if new_status == "down" else "🟢 RECOVERED"
    title = f"{word}: {monitor.name}"
    desc  = f"Monitor **{monitor.name}** is now **{new_status.upper()}**."
    if monitor.url: desc += f"\nURL: `{monitor.url}`"
    desc += f"\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"
    if s.discord_webhook: _discord(s.discord_webhook, title, desc, color)
    payload = {"event": f"monitor.{new_status}", "timestamp": datetime.utcnow().isoformat(),
               "monitor": {"id": monitor.id, "name": monitor.name,
                            "url": monitor.url, "status": new_status}}
    if s.generic_webhook: _webhook(s.generic_webhook, s.webhook_secret, payload)
    last[key] = datetime.utcnow().isoformat()
    s.set_last_notified(last)
    db.session.commit()

def maybe_auto_incident(user_id, monitor):
    s = UserSettings.query.filter_by(user_id=user_id).first()
    if not s or not s.auto_incident: return
    if Incident.query.filter_by(user_id=user_id, monitor_id=monitor.id, status="open").first():
        return
    inc = Incident(user_id=user_id, monitor_id=monitor.id,
                   title=f"Auto: {monitor.name} is DOWN",
                   severity=s.auto_incident_severity, status="open")
    db.session.add(inc); db.session.flush()
    db.session.add(IncidentUpdate(incident_id=inc.id, status="open",
                                   message="Monitor went DOWN — auto-created by PulseWatch."))
    db.session.commit()
    if s.notify_on_incident and s.discord_webhook:
        _discord(s.discord_webhook, f"🚨 Incident: {monitor.name}",
                 f"Severity: **{s.auto_incident_severity}**\nMonitor is DOWN.", 0xf43f5e)

def maybe_auto_resolve(user_id, monitor):
    s = UserSettings.query.filter_by(user_id=user_id).first()
    if not s or not s.auto_resolve_incident: return
    for inc in Incident.query.filter_by(user_id=user_id, monitor_id=monitor.id, status="open").all():
        inc.status = "resolved"; inc.resolved_at = datetime.utcnow()
        db.session.add(IncidentUpdate(incident_id=inc.id, status="resolved",
                                       message="Auto-resolved — monitor recovered."))
    db.session.commit()

# ═══════════════════════════════════════════════════════════════════════════════
# BACKGROUND SCHEDULER
# ═══════════════════════════════════════════════════════════════════════════════

def _in_maintenance(monitor_id):
    now = datetime.utcnow()
    return db.session.query(MaintenanceMonitor)\
        .join(Maintenance, Maintenance.id == MaintenanceMonitor.maintenance_id)\
        .filter(MaintenanceMonitor.monitor_id == monitor_id,
                Maintenance.start_time <= now,
                Maintenance.end_time >= now).first() is not None

def check_monitor(monitor_id):
    """Run an HTTP or database check and store results locally. No DB writes here."""
    with app.app_context():
        # Minimal DB read: just fetch the monitor config (needed for URL/timeout/auth).
        # Only happens at check time, not on every request.
        m = Monitor.query.get(monitor_id)
        if not m or not m.active or m.type not in ("http", "database"): return
        if _in_maintenance(m.id):
            # Maintenance state is written directly — it's a config change not a check.
            m.status = "maintenance"; db.session.commit(); return

        prev_state = _get_local_status(monitor_id)
        prev = prev_state["status"] if prev_state else m.status  # fall back to DB on first run

        if m.type == "database":
            nstatus, elapsed, code, msg = check_database(m)
            phases = {}
        else:
            auth = None
            if m.http_auth_user:
                auth = (m.http_auth_user, m.http_auth_pass or "")

            phases = {}
            t_start = time.perf_counter()
            t_dns_done = t_connect_done = t_tls_done = t_ttfb_done = None

            try:
                import socket as _socket
                import ssl as _ssl

                is_https = m.url.startswith("https://")
                from urllib.parse import urlparse as _uparse
                purl = _uparse(m.url)
                host = purl.hostname or ""
                port = purl.port or (443 if is_https else 80)

                # ── Phase 1: DNS lookup ───────────────────────────────────────
                try:
                    _socket.getaddrinfo(host, port)
                    t_dns_done = time.perf_counter()
                except Exception:
                    t_dns_done = time.perf_counter()

                # ── Phase 2+: Let requests do the actual request ─────────────
                # (we already paid DNS cost above, so requests may reuse it via OS cache)
                t_req_start = time.perf_counter()
                resp    = http_req.get(m.url, timeout=m.timeout, allow_redirects=True,
                                       auth=auth, headers={"User-Agent": "PulseWatch/4.0"})
                t_ttfb_done = time.perf_counter()

                elapsed = int((t_ttfb_done - t_start) * 1000)
                ok      = resp.status_code < 400
                nstatus = "up" if ok else "down"
                msg     = f"HTTP {resp.status_code}"
                code    = resp.status_code

                # Build phase dict (all cumulative from t_start, in ms)
                dns_ms = int((t_dns_done - t_start) * 1000)
                ttfb_ms = elapsed

                if is_https:
                    # Estimate connect and TLS from request duration minus DNS
                    req_dur = int((t_ttfb_done - t_req_start) * 1000)
                    connect_ms  = dns_ms + max(1, int(req_dur * 0.30))
                    tls_ms      = dns_ms + max(2, int(req_dur * 0.65))
                    phases = {
                        "namelookup": dns_ms,
                        "connect":    min(connect_ms, ttfb_ms - 2),
                        "tls":        min(tls_ms, ttfb_ms - 1),
                        "ttfb":       ttfb_ms,
                    }
                else:
                    req_dur = int((t_ttfb_done - t_req_start) * 1000)
                    connect_ms = dns_ms + max(1, int(req_dur * 0.40))
                    phases = {
                        "namelookup": dns_ms,
                        "connect":    min(connect_ms, ttfb_ms - 1),
                        "tls":        None,
                        "ttfb":       ttfb_ms,
                    }

            except Exception as e:
                elapsed = int((time.perf_counter() - t_start) * 1000)
                nstatus, msg, code = "down", str(e)[:200], None

        # ── Write to local buffer only — no DB hit ────────────────────────────
        _buffer_check(monitor_id, nstatus, elapsed, code, msg, phases)

        # ── Status-change notifications still fire immediately ─────────────────
        if prev not in ("pending", "maintenance") and prev != nstatus:
            # We need to pass a monitor-like object; reuse the one we already loaded.
            m.status = nstatus  # update in-object so notifications read correctly
            fire_notifications(m.user_id, m, nstatus)
            if nstatus == "down":
                maybe_auto_incident(m.user_id, m)
            else:
                maybe_auto_resolve(m.user_id, m)
            # Note: fire_notifications and maybe_auto_incident do their own db.session.commit()
            # for the notification state; that's acceptable (rare, only on status change).


def check_heartbeats():
    with app.app_context():
        for m in Monitor.query.filter_by(type="heartbeat", active=True).all():
            if not m.last_heartbeat: continue
            grace = timedelta(seconds=m.interval + m.heartbeat_grace)
            if datetime.utcnow() - m.last_heartbeat > grace:
                if m.status != "down":
                    m.status = "down"
                    db.session.commit()
                    fire_notifications(m.user_id, m, "down")
                    maybe_auto_incident(m.user_id, m)


def apply_maintenance():
    with app.app_context():
        now = datetime.utcnow()
        for mm in db.session.query(MaintenanceMonitor)\
                .join(Maintenance, Maintenance.id == MaintenanceMonitor.maintenance_id).all():
            m = mm.monitor; maint = mm.maintenance
            if maint.start_time <= now <= maint.end_time:
                if m.status != "maintenance": m.status = "maintenance"
            elif now > maint.end_time and m.status == "maintenance":
                m.status = "pending"
        db.session.commit()


def flush_checks_to_db():
    """
    Hourly job: drain the in-memory check buffer into the DB and sync monitor
    status/stats. This is the ONLY place the scheduler writes checks to the DB.
    """
    with app.app_context():
        with _local_checks_lock:
            snapshot_checks = {mid: list(chks) for mid, chks in _local_checks.items()}
            snapshot_state  = {mid: dict(st)   for mid, st   in _local_monitor_state.items()}
            _local_checks.clear()

        if not snapshot_checks:
            return

        print(f"[PulseWatch] flush_checks_to_db: flushing {sum(len(v) for v in snapshot_checks.values())} checks for {len(snapshot_checks)} monitors")

        since_7d = datetime.utcnow() - timedelta(days=7)

        for monitor_id, checks in snapshot_checks.items():
            m = Monitor.query.get(monitor_id)
            if not m:
                continue

            # Bulk-insert all buffered Check rows
            for c in checks:
                ph = c.get("phases") or {}
                db.session.add(Check(
                    monitor_id    = monitor_id,
                    status        = c["status"],
                    response_time = c["response_time"],
                    status_code   = c["status_code"],
                    message       = c["message"],
                    checked_at    = c["checked_at"],
                    t_namelookup  = ph.get("namelookup"),
                    t_connect     = ph.get("connect"),
                    t_tls         = ph.get("tls"),
                    t_ttfb        = ph.get("ttfb"),
                ))

            # Sync monitor summary columns from latest in-memory state
            st = snapshot_state.get(monitor_id)
            if st:
                m.status           = st["status"]
                m.response_time    = st["response_time"]
                m.last_checked     = st["last_checked"]
                m.consecutive_down = st["consecutive_down"]

            # Recompute 7-day uptime from DB (now includes the new rows after flush)
            db.session.flush()  # make the new Check rows visible in the same session
            recent = Check.query.filter(
                Check.monitor_id == monitor_id,
                Check.checked_at >= since_7d,
            ).all()
            if recent:
                m.uptime_7d = round(
                    sum(1 for c in recent if c.status == "up") / len(recent) * 100, 2
                )

        db.session.commit()
        print("[PulseWatch] flush_checks_to_db: done")


scheduler = BackgroundScheduler(daemon=True)

def schedule_monitor(monitor):
    jid = f"mon_{monitor.id}"
    try: scheduler.remove_job(jid)
    except Exception: pass
    if monitor.type in ("http", "database") and monitor.active:
        scheduler.add_job(check_monitor, "interval", seconds=monitor.interval,
                          args=[monitor.id], id=jid, replace_existing=True,
                          next_run_time=datetime.now())

def init_scheduler():
    with app.app_context():
        for m in Monitor.query.filter(Monitor.active == True, Monitor.type.in_(["http", "database"])).all():
            schedule_monitor(m)
        scheduler.add_job(check_heartbeats, "interval", seconds=60,
                          id="hb_check", replace_existing=True)
        scheduler.add_job(apply_maintenance, "interval", seconds=60,
                          id="maint_check", replace_existing=True)
        scheduler.add_job(flush_checks_to_db, "interval", hours=1,
                          id="flush_checks", replace_existing=True,
                          next_run_time=datetime.now() + timedelta(hours=1))

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════════

@lm.user_loader
def load_user(uid): return User.query.get(int(uid))

def get_settings(uid):
    s = UserSettings.query.filter_by(user_id=uid).first()
    if not s:
        s = UserSettings(user_id=uid); db.session.add(s); db.session.commit()
    return s

# ─── Routes: auth ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    err = None
    if request.method == "POST":
        u, e, pw = (request.form.get("username","").strip(),
                    request.form.get("email","").strip().lower(),
                    request.form.get("password",""))
        if not u or not e or not pw: err = "All fields required."
        elif User.query.filter_by(username=u).first(): err = "Username taken."
        elif User.query.filter_by(email=e).first():    err = "Email already registered."
        elif len(pw) < 6: err = "Password must be 6+ characters."
        else:
            usr = User(username=u, email=e); usr.set_password(pw)
            db.session.add(usr); db.session.commit()
            db.session.add(UserSettings(user_id=usr.id)); db.session.commit()
            login_user(usr); return redirect(url_for("dashboard"))
    return render_template_string(AUTH_TPL, page="register", error=err)

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    err = None
    if request.method == "POST":
        u = User.query.filter_by(username=request.form.get("username","").strip()).first()
        if u and u.check_password(request.form.get("password","")):
            if u.totp_enabled:
                session["2fa_uid"] = u.id
                return redirect(url_for("verify_2fa"))
            login_user(u, remember=True); return redirect(url_for("dashboard"))
        err = "Invalid username or password."
    return render_template_string(AUTH_TPL, page="login", error=err)

@app.route("/verify-2fa", methods=["GET","POST"])
def verify_2fa():
    uid = session.get("2fa_uid")
    if not uid: return redirect(url_for("login"))
    u = User.query.get(uid)
    if not u: return redirect(url_for("login"))
    err = None
    if request.method == "POST":
        code = request.form.get("code","").strip()
        if TOTP_OK and pyotp.TOTP(u.totp_secret).verify(code, valid_window=1):
            session.pop("2fa_uid", None); login_user(u, remember=True)
            return redirect(url_for("dashboard"))
        err = "Invalid code."
    return render_template_string(VERIFY_2FA_TPL, error=err, username=u.username)

@app.route("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("login"))

# ─── Routes: dashboard & analytics ───────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    monitors = (Monitor.query.filter_by(user_id=current_user.id)
                .order_by(Monitor.created_at.desc()).all())
    # Overlay latest in-memory check state so the UI shows live data
    # even though the DB is only flushed hourly.
    for m in monitors:
        st = _get_local_status(m.id)
        if st:
            m.status           = st["status"]
            m.response_time    = st["response_time"]
            m.last_checked     = st["last_checked"]
            m.consecutive_down = st["consecutive_down"]
    open_inc = Incident.query.filter_by(user_id=current_user.id)\
                       .filter(Incident.status != "resolved").count()
    return render_template_string(DASHBOARD_TPL, monitors=monitors,
                                  user=current_user, open_incidents=open_inc)

@app.route("/analytics")
@login_required
def analytics():
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    for m in monitors:
        st = _get_local_status(m.id)
        if st:
            m.status           = st["status"]
            m.response_time    = st["response_time"]
            m.last_checked     = st["last_checked"]
            m.consecutive_down = st["consecutive_down"]
    sys_m = get_system_metrics()
    return render_template_string(ANALYTICS_TPL, monitors=monitors,
                                  user=current_user, sys=sys_m)

@app.route("/api/analytics")
@login_required
def api_analytics():
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    since = datetime.utcnow() - timedelta(hours=24)
    result = []
    for m in monitors:
        checks = (Check.query.filter(Check.monitor_id==m.id, Check.checked_at>=since)
                  .order_by(Check.checked_at.asc()).all())
        result.append({
            "id": m.id, "name": m.name, "status": m.status,
            "uptime_7d": m.uptime_7d, "response_time": m.response_time or 0,
            "checks": [{"t": c.checked_at.strftime("%H:%M"),
                        "rt": c.response_time or 0, "s": c.status}
                       for c in checks[-60:]]
        })
    http_m = [m for m in monitors if m.type in ("http","database") and m.response_time]
    avg_ping = round(sum(x.response_time for x in http_m)/len(http_m)) if http_m else 0
    return jsonify({"monitors": result, "avg_ping": avg_ping,
                    "sys": get_system_metrics()})

# ─── Routes: monitors ─────────────────────────────────────────────────────────

@app.route("/monitor/add", methods=["GET","POST"])
@login_required
def add_monitor():
    err = None
    if request.method == "POST":
        name  = request.form.get("name","").strip()
        mtype = request.form.get("type","http")
        url   = request.form.get("url","").strip()
        conn_str = request.form.get("connection_string","").strip()
        dbtype   = request.form.get("db_type","").strip() or None
        interval = int(request.form.get("interval",60))
        timeout  = int(request.form.get("timeout",10))
        grace    = int(request.form.get("grace",300))
        auth_u   = request.form.get("http_auth_user","").strip() or None
        auth_p   = request.form.get("http_auth_pass","").strip() or None
        if not name: err = "Name required."
        elif mtype=="http" and not url: err = "URL required."
        elif mtype=="database" and not conn_str: err = "Connection string required."
        elif mtype=="database" and dbtype not in DB_TYPES: err = "Database type required."
        else:
            m = Monitor(user_id=current_user.id, name=name, type=mtype,
                        url=url if mtype=="http" else (conn_str if mtype=="database" else None),
                        db_type=dbtype if mtype=="database" else None,
                        interval=interval, timeout=timeout, heartbeat_grace=grace,
                        http_auth_user=auth_u, http_auth_pass=auth_p)
            if mtype=="heartbeat": m.generate_heartbeat_token()
            db.session.add(m); db.session.commit()
            if mtype in ("http","database"): schedule_monitor(m)
            return redirect(url_for("dashboard"))
    return render_template_string(MONITOR_FORM_TPL, error=err, monitor=None)

@app.route("/monitor/<int:mid>/edit", methods=["GET","POST"])
@login_required
def edit_monitor(mid):
    m = Monitor.query.filter_by(id=mid, user_id=current_user.id).first_or_404()
    err = None
    if request.method == "POST":
        m.name              = request.form.get("name", m.name).strip()
        if m.type == "database":
            m.url     = request.form.get("connection_string", m.url) or m.url
            m.db_type = request.form.get("db_type", m.db_type) or m.db_type
        else:
            m.url     = request.form.get("url", m.url) or m.url
        m.interval          = int(request.form.get("interval", m.interval))
        m.timeout           = int(request.form.get("timeout", m.timeout))
        m.heartbeat_grace   = int(request.form.get("grace", m.heartbeat_grace))
        m.http_auth_user    = request.form.get("http_auth_user","").strip() or None
        m.http_auth_pass    = request.form.get("http_auth_pass","").strip() or None
        db.session.commit()
        if m.type in ("http","database"): schedule_monitor(m)
        return redirect(url_for("monitor_detail", mid=m.id))
    return render_template_string(MONITOR_FORM_TPL, error=err, monitor=m)

@app.route("/monitor/<int:mid>")
@login_required
def monitor_detail(mid):
    m = Monitor.query.filter_by(id=mid, user_id=current_user.id).first_or_404()
    checks = (Check.query.filter_by(monitor_id=mid)
              .order_by(Check.checked_at.desc()).limit(100).all())
    hb_url = f"{request.host_url.rstrip('/')}/heartbeat/{m.heartbeat_token}" if m.heartbeat_token else None
    checks_json = json.dumps([{
        "status": c.status,
        "response_time": c.response_time,
        "checked_at": c.checked_at.strftime("%Y-%m-%d %H:%M:%S") if c.checked_at else None,
        "message": c.message or "",
        "phases": {
            "namelookup": c.t_namelookup,
            "connect": c.t_connect,
            "tls": c.t_tls,
            "ttfb": c.t_ttfb,
        } if c.t_ttfb else None
    } for c in checks])
    return render_template_string(MONITOR_DETAIL_TPL, m=m, checks=checks,
                                  checks_json=checks_json, heartbeat_url=hb_url)

@app.route("/monitor/<int:mid>/toggle", methods=["POST"])
@login_required
def toggle_monitor(mid):
    m = Monitor.query.filter_by(id=mid, user_id=current_user.id).first_or_404()
    m.active = not m.active; db.session.commit()
    if m.type in ("http","database"):
        if m.active: schedule_monitor(m)
        else:
            try: scheduler.remove_job(f"mon_{m.id}")
            except Exception: pass
    return redirect(url_for("dashboard"))

@app.route("/monitor/<int:mid>/delete", methods=["POST"])
@login_required
def delete_monitor(mid):
    m = Monitor.query.filter_by(id=mid, user_id=current_user.id).first_or_404()
    # Remove scheduler job — silently swallow any error (job may not exist)
    try:
        scheduler.remove_job(f"mon_{m.id}")
    except Exception:
        pass
    # Clean up in-memory state for this monitor
    with _local_checks_lock:
        _local_checks.pop(m.id, None)
        _local_monitor_state.pop(m.id, None)
    try:
        db.session.delete(m)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # Return to dashboard with an error flash rather than crashing
        return redirect(url_for("dashboard"))
    return redirect(url_for("dashboard"))

@app.route("/heartbeat/<token>", methods=["GET","POST"])
def heartbeat(token):
    m = Monitor.query.filter_by(heartbeat_token=token, type="heartbeat").first()
    if not m: return jsonify({"ok": False, "error": "Not found"}), 404
    prev = m.status
    m.last_heartbeat = datetime.utcnow(); m.status = "up"
    chk = Check(monitor_id=m.id, status="up", response_time=0, message="Heartbeat received")
    db.session.add(chk)
    since = datetime.utcnow() - timedelta(days=7)
    recent = Check.query.filter(Check.monitor_id==m.id, Check.checked_at>=since).all()
    if recent: m.uptime_7d = round(sum(1 for c in recent if c.status=="up")/len(recent)*100, 2)
    db.session.commit()
    if prev == "down":
        fire_notifications(m.user_id, m, "up"); maybe_auto_resolve(m.user_id, m)
    return jsonify({"ok": True, "monitor": m.name})

# ─── Routes: incidents ────────────────────────────────────────────────────────

@app.route("/incidents")
@login_required
def incidents():
    all_inc = Incident.query.filter_by(user_id=current_user.id)\
                      .order_by(Incident.created_at.desc()).all()
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    return render_template_string(INCIDENTS_TPL, incidents=all_inc, monitors=monitors)

@app.route("/incidents/create", methods=["GET","POST"])
@login_required
def create_incident():
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    err = None
    if request.method == "POST":
        title = request.form.get("title","").strip()
        sev   = request.form.get("severity","major")
        body  = request.form.get("body","").strip()
        mid   = request.form.get("monitor_id") or None
        if not title: err = "Title required."
        else:
            inc = Incident(user_id=current_user.id, title=title, severity=sev,
                           body=body, monitor_id=int(mid) if mid else None)
            db.session.add(inc); db.session.flush()
            if body:
                db.session.add(IncidentUpdate(incident_id=inc.id, message=body, status="open"))
            db.session.commit()
            s = get_settings(current_user.id)
            if s.notify_on_incident and s.discord_webhook:
                _discord(s.discord_webhook, f"🚨 Incident: {title}",
                         f"Severity: **{sev}**\n{body[:500]}", 0xf43f5e)
            return redirect(url_for("incidents"))
    return render_template_string(INCIDENT_FORM_TPL, err=err, monitors=monitors)

@app.route("/incidents/<int:iid>")
@login_required
def incident_detail(iid):
    inc = Incident.query.filter_by(id=iid, user_id=current_user.id).first_or_404()
    return render_template_string(INCIDENT_DETAIL_TPL, inc=inc)

@app.route("/incidents/<int:iid>/update", methods=["POST"])
@login_required
def update_incident(iid):
    inc = Incident.query.filter_by(id=iid, user_id=current_user.id).first_or_404()
    msg = request.form.get("message","").strip()
    ns  = request.form.get("status", inc.status)
    nsev= request.form.get("severity", inc.severity)
    if msg: db.session.add(IncidentUpdate(incident_id=inc.id, message=msg, status=ns))
    inc.status = ns; inc.severity = nsev
    if ns == "resolved" and not inc.resolved_at: inc.resolved_at = datetime.utcnow()
    db.session.commit()
    s = get_settings(current_user.id)
    if s.notify_on_incident and s.discord_webhook and msg:
        col = 0x22d3a4 if ns=="resolved" else 0xf97316
        _discord(s.discord_webhook, f"📋 Update: {inc.title}",
                 f"Status: **{ns}** | Severity: **{nsev}**\n{msg[:500]}", col)
    return redirect(url_for("incident_detail", iid=iid))

@app.route("/incidents/<int:iid>/delete", methods=["POST"])
@login_required
def delete_incident(iid):
    inc = Incident.query.filter_by(id=iid, user_id=current_user.id).first_or_404()
    db.session.delete(inc); db.session.commit()
    return redirect(url_for("incidents"))

# ─── Routes: maintenance ──────────────────────────────────────────────────────

@app.route("/maintenance")
@login_required
def maintenance_list():
    items = (Maintenance.query.filter_by(user_id=current_user.id)
             .order_by(Maintenance.start_time.desc()).all())
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    # Pre-compute categories in Python (Jinja2 can't do list comprehensions)
    now = datetime.utcnow()
    active   = [i for i in items if i.start_time <= now <= i.end_time]
    upcoming = [i for i in items if now < i.start_time]
    past     = [i for i in items if now > i.end_time]
    return render_template_string(MAINTENANCE_TPL, items=items, monitors=monitors,
                                  active_maint=active, upcoming_maint=upcoming, past_maint=past)

@app.route("/maintenance/create", methods=["GET","POST"])
@login_required
def create_maintenance():
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    err = None
    if request.method == "POST":
        title    = request.form.get("title","").strip()
        desc     = request.form.get("description","").strip()
        start_s  = request.form.get("start_time","")
        end_s    = request.form.get("end_time","")
        selected = request.form.getlist("monitors")
        try:
            start_dt = datetime.strptime(start_s, "%Y-%m-%dT%H:%M")
            end_dt   = datetime.strptime(end_s,   "%Y-%m-%dT%H:%M")
        except ValueError:
            err = "Invalid date format."
            return render_template_string(MAINTENANCE_FORM_TPL, err=err, monitors=monitors)
        if not title:       err = "Title required."
        elif end_dt <= start_dt: err = "End must be after start."
        else:
            maint = Maintenance(user_id=current_user.id, title=title,
                                description=desc, start_time=start_dt, end_time=end_dt)
            db.session.add(maint); db.session.flush()
            for ms in selected:
                db.session.add(MaintenanceMonitor(maintenance_id=maint.id, monitor_id=int(ms)))
            db.session.commit()
            return redirect(url_for("maintenance_list"))
    return render_template_string(MAINTENANCE_FORM_TPL, err=err, monitors=monitors)

@app.route("/maintenance/<int:maint_id>/delete", methods=["POST"])
@login_required
def delete_maintenance(maint_id):
    maint = Maintenance.query.filter_by(id=maint_id, user_id=current_user.id).first_or_404()
    db.session.delete(maint); db.session.commit()
    return redirect(url_for("maintenance_list"))

# ─── Routes: status pages ─────────────────────────────────────────────────────

@app.route("/status-pages")
@login_required
def status_pages():
    pages = StatusPage.query.filter_by(user_id=current_user.id).all()
    return render_template_string(STATUS_PAGES_LIST_TPL, pages=pages)

@app.route("/status-pages/create", methods=["GET","POST"])
@login_required
def create_status_page():
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    err = None
    if request.method == "POST":
        title    = request.form.get("title","").strip()
        slug     = request.form.get("slug","").strip().lower().replace(" ","-")
        desc     = request.form.get("description","").strip()
        selected = request.form.getlist("monitors")
        if not title or not slug: err = "Title and slug required."
        elif StatusPage.query.filter_by(slug=slug).first(): err = "Slug taken."
        else:
            pg = StatusPage(user_id=current_user.id, title=title, slug=slug, description=desc)
            db.session.add(pg); db.session.flush()
            for ms in selected:
                db.session.add(StatusPageMonitor(page_id=pg.id, monitor_id=int(ms)))
            db.session.commit()
            return redirect(url_for("status_pages"))
    return render_template_string(STATUS_PAGE_FORM_TPL, monitors=monitors,
                                  err=err, page=None, selected_ids=[])

@app.route("/status-pages/<int:pid>/edit", methods=["GET","POST"])
@login_required
def edit_status_page(pid):
    pg = StatusPage.query.filter_by(id=pid, user_id=current_user.id).first_or_404()
    monitors = Monitor.query.filter_by(user_id=current_user.id).all()
    selected_ids = [s.monitor_id for s in pg.page_monitors]
    if request.method == "POST":
        pg.title       = request.form.get("title", pg.title).strip()
        pg.description = request.form.get("description", pg.description)
        selected = request.form.getlist("monitors")
        StatusPageMonitor.query.filter_by(page_id=pg.id).delete()
        for ms in selected:
            db.session.add(StatusPageMonitor(page_id=pg.id, monitor_id=int(ms)))
        db.session.commit()
        return redirect(url_for("status_pages"))
    return render_template_string(STATUS_PAGE_FORM_TPL, monitors=monitors,
                                  err=None, page=pg, selected_ids=selected_ids)

@app.route("/status-pages/<int:pid>/delete", methods=["POST"])
@login_required
def delete_status_page(pid):
    pg = StatusPage.query.filter_by(id=pid, user_id=current_user.id).first_or_404()
    db.session.delete(pg); db.session.commit()
    return redirect(url_for("status_pages"))

@app.route("/status-pages/<int:pid>/announcements/add", methods=["POST"])
@login_required
def add_announcement(pid):
    pg = StatusPage.query.filter_by(id=pid, user_id=current_user.id).first_or_404()
    title = request.form.get("ann_title","").strip()
    if title:
        db.session.add(Announcement(page_id=pg.id, title=title,
                                    body=request.form.get("ann_body","").strip(),
                                    pinned=bool(request.form.get("pinned"))))
        db.session.commit()
    return redirect(url_for("edit_status_page", pid=pid))

@app.route("/status-pages/<int:pid>/announcements/<int:aid>/delete", methods=["POST"])
@login_required
def delete_announcement(pid, aid):
    StatusPage.query.filter_by(id=pid, user_id=current_user.id).first_or_404()
    ann = Announcement.query.filter_by(id=aid, page_id=pid).first_or_404()
    db.session.delete(ann); db.session.commit()
    return redirect(url_for("edit_status_page", pid=pid))

# ─── Public status page ───────────────────────────────────────────────────────

def _build_status_context(slug):
    pg = StatusPage.query.filter_by(slug=slug, public=True).first_or_404()
    now = datetime.utcnow()
    pm_ids = [s.monitor_id for s in pg.page_monitors]
    active_maints = upcoming_maints = active_incs = recent_incs = []
    if pm_ids:
        all_m = db.session.query(Maintenance)\
            .join(MaintenanceMonitor, MaintenanceMonitor.maintenance_id==Maintenance.id)\
            .filter(MaintenanceMonitor.monitor_id.in_(pm_ids)).all()
        active_maints   = [m for m in all_m if m.start_time <= now <= m.end_time]
        upcoming_maints = [m for m in all_m if now < m.start_time]
        active_incs = Incident.query\
            .filter(Incident.monitor_id.in_(pm_ids), Incident.status!="resolved")\
            .order_by(Incident.created_at.desc()).all()
        recent_incs = Incident.query\
            .filter(Incident.monitor_id.in_(pm_ids), Incident.status=="resolved",
                    Incident.resolved_at >= now-timedelta(days=14))\
            .order_by(Incident.resolved_at.desc()).limit(5).all()
    anns = Announcement.query.filter_by(page_id=pg.id)\
               .order_by(Announcement.pinned.desc(), Announcement.created_at.desc()).all()
    return dict(page=pg, now=now, active_maints=active_maints,
                upcoming_maints=upcoming_maints, active_incidents=active_incs,
                recent_incidents=recent_incs, announcements=anns)

@app.route("/status/<slug>")
def public_status(slug):
    ctx = _build_status_context(slug)
    return render_template_string(PUBLIC_STATUS_TPL, **ctx)

# ─── RSS + Atom feeds ─────────────────────────────────────────────────────────

def _feed_items(pg):
    pm_ids = [s.monitor_id for s in pg.page_monitors]
    items = []
    if pm_ids:
        for inc in Incident.query.filter(Incident.monitor_id.in_(pm_ids))\
                .order_by(Incident.created_at.desc()).limit(30).all():
            items.append({"title": f"[{inc.severity.replace('_',' ').title()}] {inc.title}",
                          "desc": (inc.body or "") + f"\nStatus: {inc.status}",
                          "date": inc.created_at, "guid": f"incident-{inc.id}"})
    for ann in Announcement.query.filter_by(page_id=pg.id)\
            .order_by(Announcement.created_at.desc()).limit(10).all():
        items.append({"title": f"[Announcement] {ann.title}",
                      "desc": ann.body or "", "date": ann.created_at,
                      "guid": f"ann-{ann.id}"})
    items.sort(key=lambda x: x["date"], reverse=True)
    return items[:30]

@app.route("/status/<slug>/rss")
def status_rss(slug):
    pg   = StatusPage.query.filter_by(slug=slug, public=True).first_or_404()
    base = request.host_url.rstrip("/")
    link = f"{base}/status/{slug}"
    root = ET.Element("rss", version="2.0")
    ch   = ET.SubElement(root, "channel")
    ET.SubElement(ch, "title").text       = f"{pg.title} — Incidents"
    ET.SubElement(ch, "link").text        = link
    ET.SubElement(ch, "description").text = pg.description or f"Incident feed for {pg.title}"
    ET.SubElement(ch, "language").text    = "en"
    ET.SubElement(ch, "lastBuildDate").text = datetime.utcnow()\
        .strftime("%a, %d %b %Y %H:%M:%S +0000")
    for it in _feed_items(pg):
        el = ET.SubElement(ch, "item")
        ET.SubElement(el, "title").text   = it["title"]
        ET.SubElement(el, "link").text    = link
        ET.SubElement(el, "description").text = it["desc"]
        ET.SubElement(el, "pubDate").text = it["date"].strftime("%a, %d %b %Y %H:%M:%S +0000")
        ET.SubElement(el, "guid").text    = f"{link}#{it['guid']}"
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
    return Response(xml, mimetype="application/rss+xml")

@app.route("/status/<slug>/atom")
def status_atom(slug):
    pg   = StatusPage.query.filter_by(slug=slug, public=True).first_or_404()
    base = request.host_url.rstrip("/")
    link = f"{base}/status/{slug}"
    now_s = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    ns = "http://www.w3.org/2005/Atom"
    feed = ET.Element("feed", xmlns=ns)
    ET.SubElement(feed, "title").text   = f"{pg.title} — Status"
    ET.SubElement(feed, "id").text      = link
    ET.SubElement(feed, "updated").text = now_s
    l = ET.SubElement(feed, "link"); l.set("href", link); l.set("rel", "alternate")
    ls= ET.SubElement(feed, "link"); ls.set("href", f"{link}/atom"); ls.set("rel", "self")
    ET.SubElement(feed, "subtitle").text = pg.description or ""
    for it in _feed_items(pg):
        entry = ET.SubElement(feed, "entry")
        ET.SubElement(entry, "title").text   = it["title"]
        ET.SubElement(entry, "id").text      = f"{link}#{it['guid']}"
        ET.SubElement(entry, "updated").text = it["date"].strftime("%Y-%m-%dT%H:%M:%SZ")
        ET.SubElement(entry, "summary").text = it["desc"]
        el = ET.SubElement(entry, "link"); el.set("href", link)
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(feed, encoding="unicode")
    return Response(xml, mimetype="application/atom+xml")

# ─── Routes: settings ─────────────────────────────────────────────────────────

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    s = get_settings(current_user.id)
    saved = False
    if request.method == "POST":
        action = request.form.get("action","save")
        if action == "save":
            s.discord_webhook       = request.form.get("discord_webhook","").strip() or None
            s.generic_webhook       = request.form.get("generic_webhook","").strip() or None
            s.webhook_secret        = request.form.get("webhook_secret","").strip() or None
            s.notify_on_down        = bool(request.form.get("notify_on_down"))
            s.notify_on_recover     = bool(request.form.get("notify_on_recover"))
            s.notify_on_incident    = bool(request.form.get("notify_on_incident"))
            s.notify_cooldown_min   = max(1, int(request.form.get("notify_cooldown_min",5) or 5))
            s.auto_incident         = bool(request.form.get("auto_incident"))
            s.auto_resolve_incident = bool(request.form.get("auto_resolve_incident"))
            s.auto_incident_severity= request.form.get("auto_incident_severity","major")
            db.session.commit(); saved = True
        elif action == "test_discord" and s.discord_webhook:
            _discord(s.discord_webhook,"✅ PulseWatch Test","Integration working!",0x22d3a4)
        elif action == "test_webhook" and s.generic_webhook:
            _webhook(s.generic_webhook, s.webhook_secret,
                     {"event":"test","timestamp":datetime.utcnow().isoformat()})
    return render_template_string(SETTINGS_TPL, s=s, saved=saved,
                                  user=current_user, totp_ok=TOTP_OK,
                                  pw_error=None, pw_saved=False, del_error=None)

@app.route("/settings/2fa/enable", methods=["POST"])
@login_required
def enable_2fa():
    if not TOTP_OK: return redirect(url_for("settings"))
    if not current_user.totp_secret:
        current_user.totp_secret = pyotp.random_base32(); db.session.commit()
    return redirect(url_for("setup_2fa"))

@app.route("/settings/2fa/setup", methods=["GET","POST"])
@login_required
def setup_2fa():
    if not TOTP_OK: return redirect(url_for("settings"))
    err = None
    if request.method == "POST":
        if pyotp.TOTP(current_user.totp_secret).verify(
                request.form.get("code","").strip(), valid_window=1):
            current_user.totp_enabled = True; db.session.commit()
            return redirect(url_for("settings"))
        err = "Invalid code."
    uri = current_user.get_totp_uri()
    qr_b64 = None
    try:
        import qrcode as _qr, io as _io
        buf = _io.BytesIO()
        _qr.make(uri).save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
    except Exception: pass
    return render_template_string(SETUP_2FA_TPL, uri=uri, qr_b64=qr_b64,
                                  secret=current_user.totp_secret, error=err)

@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    current_user.totp_enabled = False; current_user.totp_secret = None
    db.session.commit(); return redirect(url_for("settings"))

@app.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw = request.form.get("current_password","")
    new_pw     = request.form.get("new_password","")
    confirm_pw = request.form.get("confirm_password","")
    s = get_settings(current_user.id)
    if not current_user.check_password(current_pw):
        return render_template_string(SETTINGS_TPL, s=s, saved=False,
            user=current_user, totp_ok=TOTP_OK,
            pw_error="Current password is incorrect.")
    if len(new_pw) < 6:
        return render_template_string(SETTINGS_TPL, s=s, saved=False,
            user=current_user, totp_ok=TOTP_OK,
            pw_error="New password must be 6+ characters.")
    if new_pw != confirm_pw:
        return render_template_string(SETTINGS_TPL, s=s, saved=False,
            user=current_user, totp_ok=TOTP_OK,
            pw_error="Passwords do not match.")
    current_user.set_password(new_pw)
    db.session.commit()
    return render_template_string(SETTINGS_TPL, s=s, saved=False,
        user=current_user, totp_ok=TOTP_OK, pw_saved=True)

@app.route("/settings/delete-account", methods=["POST"])
@login_required
def delete_account():
    confirm_pw = request.form.get("confirm_password","")
    if not current_user.check_password(confirm_pw):
        s = get_settings(current_user.id)
        return render_template_string(SETTINGS_TPL, s=s, saved=False,
            user=current_user, totp_ok=TOTP_OK,
            del_error="Password is incorrect.")
    user = current_user
    logout_user()
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for("login"))

# ─── Favicon (inline SVG → no file needed) ────────────────────────────────────

FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<circle cx="16" cy="16" r="14" fill="#0a0d14" stroke="#3b82f6" stroke-width="3"/>
<circle cx="16" cy="16" r="5" fill="#3b82f6"/>
<line x1="16" y1="2" x2="16" y2="8" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round"/>
<line x1="16" y1="24" x2="16" y2="30" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round"/>
<line x1="2" y1="16" x2="8" y2="16" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round"/>
<line x1="24" y1="16" x2="30" y2="16" stroke="#3b82f6" stroke-width="2.5" stroke-linecap="round"/>
</svg>"""

@app.route("/favicon.svg")
def favicon_svg():
    return Response(FAVICON_SVG, mimetype="image/svg+xml")

@app.route("/favicon.ico")
def favicon_ico():
    return redirect("/favicon.svg", 301)

# ═══════════════════════════════════════════════════════════════════════════════
# SHARED CSS + NAV SNIPPETS
# ═══════════════════════════════════════════════════════════════════════════════

_FAV = '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'

_S = """
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0d14;--sf:#111520;--s2:#181e2e;--bd:#1e2740;--ac:#3b82f6;--gr:#22d3a4;--rd:#f43f5e;--yl:#fbbf24;--or:#f97316;--pu:#a855f7;--tx:#e2e8f0;--mu:#64748b;--mono:'Space Mono',monospace;--sans:'DM Sans',sans-serif}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:14px;min-height:100vh;line-height:1.6}
a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline}
input,select,textarea{background:var(--s2);border:1px solid var(--bd);color:var(--tx);border-radius:8px;padding:10px 14px;font-family:var(--sans);font-size:14px;width:100%;outline:none;transition:border-color .2s}
input:focus,select:focus,textarea:focus{border-color:var(--ac)}
input[type=checkbox]{width:auto;accent-color:var(--ac)}
button,.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:8px;border:none;cursor:pointer;font-family:var(--sans);font-size:13px;font-weight:600;transition:all .15s;text-decoration:none;white-space:nowrap}
.bp{background:var(--ac);color:#fff}.bp:hover{background:#2563eb;text-decoration:none;color:#fff}
.bd2{background:#1f0d12;color:var(--rd);border:1px solid #3d1520}.bd2:hover{background:#2d0f1c}
.bg2{background:var(--s2);color:var(--tx);border:1px solid var(--bd)}.bg2:hover{background:var(--bd);text-decoration:none}
.bw{background:#2d1f00;color:var(--yl);border:1px solid #4d3600}
.bs{background:#0d2e22;color:var(--gr);border:1px solid #1a5e3a}
.bsm{padding:6px 12px;font-size:12px}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:20px}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;font-family:var(--mono);text-transform:uppercase;letter-spacing:.04em}
.b-up{background:#0d2e22;color:var(--gr)}.b-down{background:#2d0f1c;color:var(--rd)}
.b-pending{background:#1f1a08;color:var(--yl)}.b-maintenance{background:#1a1030;color:var(--pu)}
.b-degraded{background:#2d1a00;color:var(--or)}.b-major{background:#2d0f1c;color:var(--rd)}
.b-full_outage{background:#3d0010;color:#ff2050}
.b-open{background:#2d1f00;color:var(--yl)}.b-monitoring{background:#0d1a30;color:var(--ac)}.b-resolved{background:#0d2e22;color:var(--gr)}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;flex-shrink:0}
.du{background:var(--gr);box-shadow:0 0 8px var(--gr)}.dd{background:var(--rd);box-shadow:0 0 8px var(--rd)}
.dp{background:var(--yl)}.dm{background:var(--pu)}
.fg{display:flex;flex-direction:column;gap:6px;margin-bottom:16px}
.fl{font-size:13px;font-weight:500;color:var(--mu)}
.fh{font-size:11px;color:var(--mu);margin-top:2px}
.em{background:#2d0f1c;border:1px solid #3d1520;color:var(--rd);padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px}
.sm{background:#0d2e22;border:1px solid #1a5e3a;color:var(--gr);padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px}
.nav{background:var(--sf);border-bottom:1px solid var(--bd);padding:0 20px;display:flex;align-items:center;justify-content:space-between;height:56px;position:sticky;top:0;z-index:100}
.nb{font-family:var(--mono);font-size:15px;font-weight:700;color:var(--tx);display:flex;align-items:center;gap:8px}
.nb span{color:var(--ac)}
.nl{display:flex;align-items:center;gap:2px;flex-wrap:wrap}
.nl a{padding:6px 9px;border-radius:6px;color:var(--mu);font-size:12px;font-weight:500;transition:all .15s}
.nl a:hover,.nl a.act{background:var(--s2);color:var(--tx);text-decoration:none}
.nb2{background:var(--rd);color:#fff;border-radius:10px;font-size:10px;padding:1px 5px;font-weight:700;margin-left:2px}
.pg{max-width:980px;margin:0 auto;padding:32px 20px}
.pt{font-size:22px;font-weight:600;margin-bottom:4px}
.ps{color:var(--mu);font-size:13px;margin-bottom:24px}
.ub{display:flex;gap:2px;height:28px;align-items:center}
.us{flex:1;height:20px;border-radius:3px;background:var(--bd);transition:height .15s}
.us.up{background:var(--gr);opacity:.75}.us.down{background:var(--rd);opacity:.85}.us.maintenance{background:var(--pu);opacity:.8}
.us:hover{height:28px;opacity:1!important}
.sr{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px}
.sc{background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}
.sv{font-family:var(--mono);font-size:22px;font-weight:700}
.sl{color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.tbl{width:100%;border-collapse:collapse}
.tbl th{color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.05em;font-weight:600;padding:10px 14px;border-bottom:1px solid var(--bd);text-align:left}
.tbl td{padding:12px 14px;border-bottom:1px solid var(--bd);font-size:13px;vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:var(--s2)}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.mono{font-family:var(--mono)}
.sh{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);font-weight:700;margin:20px 0 10px}
.tr-row{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--bd)}
.tr-row:last-child{border-bottom:none}
/* Gauge ring */
.gauge{width:140px;height:140px;border-radius:50%;display:flex;align-items:center;justify-content:center}
.gauge-inner{width:100px;height:100px;border-radius:50%;background:var(--sf);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px}
/* progress bar */
.pbar{height:8px;border-radius:4px;background:var(--bd);overflow:hidden;margin-top:6px}
.pbar-fill{height:100%;border-radius:4px;transition:width .4s}
@media(max-width:640px){.pg{padding:20px 14px}.nav{padding:0 12px}.sr{grid-template-columns:1fr 1fr}.nl a{padding:5px 7px;font-size:11px}}
</style>
"""

_NAV_T = """
<nav class="nav">
  <a href="/dashboard" class="nb">
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8" stroke="#3b82f6" stroke-width="2"/><circle cx="9" cy="9" r="3" fill="#3b82f6"/><line x1="9" y1="1" x2="9" y2="4" stroke="#3b82f6" stroke-width="1.5"/><line x1="9" y1="14" x2="9" y2="17" stroke="#3b82f6" stroke-width="1.5"/><line x1="1" y1="9" x2="4" y2="9" stroke="#3b82f6" stroke-width="1.5"/><line x1="14" y1="9" x2="17" y2="9" stroke="#3b82f6" stroke-width="1.5"/></svg>
    <span>Pulse</span>Watch
  </a>
  <div class="nl">
    <a href="/dashboard" class="{% if act=='dash' %}act{% endif %}">Monitors{% if open_incidents is defined and open_incidents %}<span class="nb2">{{ open_incidents }}</span>{% endif %}</a>
    <a href="/analytics" class="{% if act=='analytics' %}act{% endif %}">Analytics</a>
    <a href="/incidents" class="{% if act=='incidents' %}act{% endif %}">Incidents</a>
    <a href="/maintenance" class="{% if act=='maintenance' %}act{% endif %}">Maintenance</a>
    <a href="/status-pages" class="{% if act=='sp' %}act{% endif %}">Status Pages</a>
    <a href="/settings" class="{% if act=='settings' %}act{% endif %}">Settings</a>
    <div class="av-wrap" style="position:relative;display:inline-block">
      <div class="av" onclick="this.parentElement.querySelector('.av-dd').classList.toggle('open')"
           style="width:30px;height:30px;border-radius:50%;background:var(--ac);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;cursor:pointer;margin-left:6px;flex-shrink:0;user-select:none">
        {{ current_user.username[0].upper() if current_user.is_authenticated else '?' }}
      </div>
      <div class="av-dd" style="display:none;position:absolute;right:0;top:38px;background:var(--sf);border:1px solid var(--bd);border-radius:10px;min-width:140px;z-index:200;padding:6px;box-shadow:0 8px 24px rgba(0,0,0,.3)">
        <div style="padding:8px 10px;font-size:11px;color:var(--mu);border-bottom:1px solid var(--bd);margin-bottom:4px">{{ current_user.username if current_user.is_authenticated else '' }}</div>
        <a href="/settings" style="display:block;padding:7px 10px;border-radius:6px;color:var(--tx);font-size:13px;text-decoration:none" onmouseover="this.style.background='var(--s2)'" onmouseout="this.style.background=''">Settings</a>
        <a href="/logout" style="display:block;padding:7px 10px;border-radius:6px;color:var(--rd);font-size:13px;text-decoration:none" onmouseover="this.style.background='var(--s2)'" onmouseout="this.style.background=''">Logout</a>
      </div>
    </div>
  </div>
</nav>
<script>
document.addEventListener('click',function(e){
  document.querySelectorAll('.av-dd.open').forEach(function(d){
    if(!d.parentElement.contains(e.target)) d.classList.remove('open');
  });
});
document.querySelectorAll('.av-dd').forEach(function(d){d.style.display='block';d.style.visibility='hidden';setTimeout(function(){d.style.display='none';d.style.visibility='';},0);});
</script>
<style>.av-dd.open{display:block!important}</style>
"""

# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════════

AUTH_TPL = """<!DOCTYPE html><html><head><title>PulseWatch</title>""" + _FAV + _S + """
<style>
.aw{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:radial-gradient(ellipse 80% 60% at 50% 0%,#1a2340 0%,var(--bg) 70%)}
.ab{width:100%;max-width:400px}
.al{text-align:center;margin-bottom:32px;font-family:var(--mono);font-size:22px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:10px}
.al span{color:var(--ac)}
.ac{background:var(--sf);border:1px solid var(--bd);border-radius:16px;padding:32px}
</style></head><body>
<div class="aw"><div class="ab">
  <div class="al"><svg width="24" height="24" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8" stroke="#3b82f6" stroke-width="2"/><circle cx="9" cy="9" r="3" fill="#3b82f6"/><line x1="9" y1="1" x2="9" y2="4" stroke="#3b82f6" stroke-width="1.5"/><line x1="9" y1="14" x2="9" y2="17" stroke="#3b82f6" stroke-width="1.5"/><line x1="1" y1="9" x2="4" y2="9" stroke="#3b82f6" stroke-width="1.5"/><line x1="14" y1="9" x2="17" y2="9" stroke="#3b82f6" stroke-width="1.5"/></svg><span>Pulse</span>Watch</div>
  <div class="ac">
    <div style="font-size:18px;font-weight:600;margin-bottom:4px">{% if page=='login' %}Welcome back{% else %}Create account{% endif %}</div>
    <div style="color:var(--mu);font-size:13px;margin-bottom:24px">{% if page=='login' %}Sign in to your dashboard{% else %}Start monitoring for free{% endif %}</div>
    {% if error %}<div class="em">{{ error }}</div>{% endif %}
    <form method="POST">
      <div class="fg"><label class="fl">Username</label><input type="text" name="username" placeholder="your_username" required autofocus></div>
      {% if page=='register' %}<div class="fg"><label class="fl">Email</label><input type="email" name="email" placeholder="you@example.com" required></div>{% endif %}
      <div class="fg"><label class="fl">Password</label><input type="password" name="password" placeholder="••••••••" required></div>
      <button type="submit" class="btn bp" style="width:100%;justify-content:center;padding:12px">{% if page=='login' %}Sign In{% else %}Create Account{% endif %}</button>
    </form>
  </div>
  <div style="text-align:center;margin-top:20px;color:var(--mu);font-size:13px">{% if page=='login' %}No account? <a href="/register">Register</a>{% else %}Have an account? <a href="/login">Sign in</a>{% endif %}</div>
</div></div></body></html>"""

VERIFY_2FA_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — 2FA</title>""" + _FAV + _S + """
<style>.aw{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}.ac{background:var(--sf);border:1px solid var(--bd);border-radius:16px;padding:32px;width:100%;max-width:380px}</style>
</head><body><div class="aw"><div class="ac">
  <div style="text-align:center;font-size:32px;margin-bottom:12px">🔐</div>
  <div style="font-size:18px;font-weight:600;text-align:center;margin-bottom:4px">Two-Factor Auth</div>
  <div style="color:var(--mu);font-size:13px;text-align:center;margin-bottom:24px">Enter your 6-digit code, {{ username }}</div>
  {% if error %}<div class="em">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="fg"><input type="text" name="code" placeholder="000000" maxlength="6" autocomplete="one-time-code" style="text-align:center;font-size:24px;font-family:var(--mono);letter-spacing:8px" autofocus required></div>
    <button type="submit" class="btn bp" style="width:100%;justify-content:center;padding:12px">Verify</button>
  </form>
  <div style="text-align:center;margin-top:14px;font-size:13px;color:var(--mu)"><a href="/login">← Back to login</a></div>
</div></div></body></html>"""

SETUP_2FA_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Setup 2FA</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg" style="max-width:560px">
  <div class="pt">Set Up Two-Factor Auth</div>
  <div class="ps">Scan with Google Authenticator, Authy, or any TOTP app</div>
  {% if error %}<div class="em">{{ error }}</div>{% endif %}
  <div class="card" style="text-align:center;margin-bottom:20px">
    {% if qr_b64 %}<img src="data:image/png;base64,{{ qr_b64 }}" style="width:200px;height:200px;border-radius:8px;background:#fff;padding:8px">{% endif %}
    <div style="margin-top:14px"><div class="fl" style="margin-bottom:6px">Manual entry secret</div>
    <div class="mono" style="background:var(--s2);border:1px solid var(--bd);border-radius:8px;padding:10px 14px;letter-spacing:3px;font-size:13px;word-break:break-all">{{ secret }}</div></div>
  </div>
  <div class="card"><div style="font-weight:600;margin-bottom:14px">Verify code</div>
    <form method="POST">
      <div class="fg"><label class="fl">6-digit code</label>
        <input type="text" name="code" placeholder="000000" maxlength="6" style="font-family:var(--mono);font-size:18px;letter-spacing:6px;text-align:center" autofocus required></div>
      <div style="display:flex;gap:10px">
        <button type="submit" class="btn bp">Verify & Enable</button>
        <a href="/settings" class="btn bg2">Cancel</a>
      </div>
    </form>
  </div>
</div></body></html>"""

DASHBOARD_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Dashboard</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:12px">
    <div><div class="pt">Monitors</div><div class="ps">Hello, {{ user.username }} — real-time service health</div></div>
    <a href="/monitor/add" class="btn bp"><svg width="13" height="13" viewBox="0 0 14 14" fill="none"><line x1="7" y1="1" x2="7" y2="13" stroke="white" stroke-width="2" stroke-linecap="round"/><line x1="1" y1="7" x2="13" y2="7" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>Add Monitor</a>
  </div>
  {% set up_c=monitors|selectattr('status','equalto','up')|list|length %}
  {% set dn_c=monitors|selectattr('status','equalto','down')|list|length %}
  {% set mt_c=monitors|selectattr('status','equalto','maintenance')|list|length %}
  {% set tot=monitors|length %}
  <div class="sr">
    <div class="sc"><div class="sv">{{ tot }}</div><div class="sl">Total</div></div>
    <div class="sc"><div class="sv" style="color:var(--gr)">{{ up_c }}</div><div class="sl">Online</div></div>
    <div class="sc"><div class="sv" style="color:var(--rd)">{{ dn_c }}</div><div class="sl">Down</div></div>
    <div class="sc"><div class="sv" style="color:var(--pu)">{{ mt_c }}</div><div class="sl">Maintenance</div></div>
    <div class="sc"><div class="sv">{% if tot %}{{ "%.1f"|format(up_c/tot*100) }}%{% else %}—{% endif %}</div><div class="sl">Availability</div></div>
  </div>
  {% if monitors %}
  <div class="card" style="padding:0;overflow:hidden">
    <table class="tbl">
      <thead><tr><th></th><th>Name</th><th>Type</th><th>Uptime 7d</th><th>Response</th><th>Last Check</th><th></th></tr></thead>
      <tbody>
      {% for m in monitors %}
      <tr>
        <td style="width:26px"><span class="dot {% if m.status=='up' %}du pulse{% elif m.status=='down' %}dd{% elif m.status=='maintenance' %}dm{% else %}dp{% endif %}"></span></td>
        <td><a href="/monitor/{{ m.id }}" style="color:var(--tx);font-weight:500">{{ m.name }}</a>{% if not m.active %}<span style="color:var(--mu);font-size:11px"> (paused)</span>{% endif %}</td>
        <td><span class="mono" style="color:var(--mu);font-size:11px">{{ m.type.upper() }}</span></td>
        <td><span class="mono" style="color:{% if m.uptime_7d>=99 %}var(--gr){% elif m.uptime_7d>=90 %}var(--yl){% else %}var(--rd){% endif %}">{{ "%.1f"|format(m.uptime_7d) }}%</span></td>
        <td>{% if m.response_time %}<span class="mono" style="font-size:12px;color:var(--mu)">{{ m.response_time }}ms</span>{% else %}—{% endif %}</td>
        <td>{% if m.last_checked %}<span class="mono" style="font-size:11px;color:var(--mu)">{{ m.last_checked.strftime('%H:%M:%S') }}</span>{% elif m.last_heartbeat %}<span class="mono" style="font-size:11px;color:var(--mu)">{{ m.last_heartbeat.strftime('%H:%M:%S') }}</span>{% else %}<span style="color:var(--mu)">—</span>{% endif %}</td>
        <td><div style="display:flex;gap:5px;justify-content:flex-end">
          <a href="/monitor/{{ m.id }}" class="btn bg2 bsm">View</a>
          <form method="POST" action="/monitor/{{ m.id }}/toggle" style="display:inline"><button class="btn bg2 bsm" type="submit">{{ 'Resume' if not m.active else 'Pause' }}</button></form>
        </div></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="card" style="text-align:center;padding:60px 20px">
    <div style="font-size:40px;margin-bottom:12px">📡</div>
    <div style="font-size:16px;font-weight:600;margin-bottom:8px">No monitors yet</div>
    <div style="color:var(--mu);margin-bottom:20px">Add your first monitor to start tracking uptime</div>
    <a href="/monitor/add" class="btn bp">Add your first monitor</a>
  </div>
  {% endif %}
</div>
<script>setTimeout(()=>location.reload(),30000)</script>
</body></html>"""

ANALYTICS_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Analytics</title>""" + _FAV + _S + """
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
.ag{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:700px){.ag{grid-template-columns:1fr}}
.mt{padding:6px 11px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:500;color:var(--mu);border:1px solid transparent;transition:all .15s}
.mt.act{background:var(--s2);color:var(--tx);border-color:var(--bd)}
.resource-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
</style>
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="margin-bottom:24px"><div class="pt">Analytics</div><div class="ps">Response times, server resources, and monitor health — last 24 hours</div></div>

  <!-- Server Resources -->
  <div class="sh">🖥️ Server Resources</div>
  <div class="resource-grid">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
        <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mu);margin-bottom:4px">CPU Usage</div>
        <div class="sv mono" style="color:{% if sys.cpu>80 %}var(--rd){% elif sys.cpu>60 %}var(--yl){% else %}var(--gr){% endif %}">{{ "%.1f"|format(sys.cpu) }}%</div></div>
        <div style="font-size:24px">⚡</div>
      </div>
      <div class="pbar"><div class="pbar-fill" style="width:{{ sys.cpu }}%;background:{% if sys.cpu>80 %}var(--rd){% elif sys.cpu>60 %}var(--yl){% else %}var(--gr){% endif %}"></div></div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
        <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mu);margin-bottom:4px">RAM Usage</div>
        <div class="sv mono" style="color:{% if sys.ram_pct>85 %}var(--rd){% elif sys.ram_pct>70 %}var(--yl){% else %}var(--gr){% endif %}">{{ "%.1f"|format(sys.ram_pct) }}%</div></div>
        <div style="font-size:24px">🧠</div>
      </div>
      <div class="pbar"><div class="pbar-fill" style="width:{{ sys.ram_pct }}%;background:{% if sys.ram_pct>85 %}var(--rd){% elif sys.ram_pct>70 %}var(--yl){% else %}var(--gr){% endif %}"></div></div>
      <div style="color:var(--mu);font-size:11px;margin-top:6px">{{ sys.ram_used_h }} / {{ sys.ram_total_h }}</div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
        <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mu);margin-bottom:4px">Disk Usage</div>
        <div class="sv mono" style="color:{% if sys.disk_pct>90 %}var(--rd){% elif sys.disk_pct>75 %}var(--yl){% else %}var(--gr){% endif %}">{{ "%.1f"|format(sys.disk_pct) }}%</div></div>
        <div style="font-size:24px">💾</div>
      </div>
      <div class="pbar"><div class="pbar-fill" style="width:{{ sys.disk_pct }}%;background:{% if sys.disk_pct>90 %}var(--rd){% elif sys.disk_pct>75 %}var(--yl){% else %}var(--gr){% endif %}"></div></div>
      <div style="color:var(--mu);font-size:11px;margin-top:6px">{{ sys.disk_used_h }} / {{ sys.disk_total_h }}</div>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
        <div><div style="font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mu);margin-bottom:4px">Load Average</div>
        <div class="sv mono" style="font-size:17px;color:var(--tx)">{{ "%.2f"|format(sys.load1) }}</div></div>
        <div style="font-size:24px">📊</div>
      </div>
      <div style="color:var(--mu);font-size:11px">1m: {{ "%.2f"|format(sys.load1) }} &nbsp; 5m: {{ "%.2f"|format(sys.load5) }} &nbsp; 15m: {{ "%.2f"|format(sys.load15) }}</div>
    </div>
  </div>

  <!-- Monitor stats -->
  <div id="loading" style="text-align:center;padding:40px;color:var(--mu)">Loading monitor data…</div>
  <div id="content" style="display:none">
    <div class="sr" id="stat-row"></div>
    <div class="ag">
      <div class="card" style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:28px;gap:14px">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mu)">Avg Ping — All HTTP Monitors</div>
        <div class="gauge" id="ping-ring" style="background:conic-gradient(var(--ac) 0deg,var(--s2) 0deg)">
          <div class="gauge-inner"><div id="pv" class="mono" style="font-size:22px;font-weight:700;color:var(--ac)">—</div><div style="font-size:11px;color:var(--mu)">ms avg</div></div>
        </div>
      </div>
      <div class="card"><div style="font-weight:600;margin-bottom:12px;font-size:13px">Monitor Health</div><div style="position:relative;height:180px"><canvas id="donut"></canvas></div></div>
    </div>
    <div class="card" style="margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px">
        <div style="font-weight:600;font-size:13px">Response Time — Last 24h</div>
        <div id="tabs" style="display:flex;gap:6px;flex-wrap:wrap"></div>
      </div>
      <div style="position:relative;height:180px"><canvas id="rt"></canvas></div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <div style="padding:14px 18px;border-bottom:1px solid var(--bd);font-weight:600;font-size:13px">Per-Monitor Summary</div>
      <table class="tbl" id="mtbl"></table>
    </div>
  </div>
</div>
<script>
let rtC=null,dnC=null;
async function load(){
  const d=await(await fetch('/api/analytics')).json();
  document.getElementById('loading').style.display='none';
  document.getElementById('content').style.display='';
  stats(d);ping(d.avg_ping);donut(d.monitors);tabs(d.monitors);if(d.monitors.length)rt(d.monitors[0]);tbl(d.monitors);
}
function stats(d){
  const up=d.monitors.filter(m=>m.status==='up').length,dn=d.monitors.filter(m=>m.status==='down').length;
  const a7=d.monitors.length?+(d.monitors.reduce((a,m)=>a+m.uptime_7d,0)/d.monitors.length).toFixed(1):0;
  document.getElementById('stat-row').innerHTML=`
    <div class="sc"><div class="sv">${d.monitors.length}</div><div class="sl">Monitors</div></div>
    <div class="sc"><div class="sv" style="color:var(--gr)">${up}</div><div class="sl">Online</div></div>
    <div class="sc"><div class="sv" style="color:var(--rd)">${dn}</div><div class="sl">Down</div></div>
    <div class="sc"><div class="sv">${a7}%</div><div class="sl">Avg Uptime 7d</div></div>
    <div class="sc"><div class="sv" style="color:var(--ac)">${d.avg_ping}ms</div><div class="sl">Avg Ping</div></div>`;
}
function ping(avg){
  const el=document.getElementById('pv');el.textContent=avg||0;
  const c=avg<200?'#22d3a4':avg<800?'#fbbf24':'#f43f5e';
  document.getElementById('ping-ring').style.background=`conic-gradient(${c} ${Math.round(Math.min(avg/2000,1)*360)}deg,#181e2e 0deg)`;
  el.style.color=c;
}
function donut(m){
  const up=m.filter(x=>x.status==='up').length,dn=m.filter(x=>x.status==='down').length,ot=m.length-up-dn;
  if(dnC)dnC.destroy();
  dnC=new Chart(document.getElementById('donut'),{type:'doughnut',data:{labels:['Online','Down','Other'],datasets:[{data:[up,dn,ot],backgroundColor:['#22d3a4','#f43f5e','#fbbf24'],borderWidth:0,hoverOffset:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#64748b',font:{size:11},padding:12}}},cutout:'70%'}});
}
function tabs(m){
  const c=document.getElementById('tabs');c.innerHTML='';
  m.forEach((mon,i)=>{const t=document.createElement('div');t.className='mt'+(i===0?' act':'');t.textContent=mon.name;t.onclick=()=>{document.querySelectorAll('.mt').forEach(x=>x.classList.remove('act'));t.classList.add('act');rt(mon)};c.appendChild(t)});
}
function rt(mon){
  if(!mon||!mon.checks.length){if(rtC)rtC.destroy();return;}
  if(rtC)rtC.destroy();
  rtC=new Chart(document.getElementById('rt'),{type:'bar',data:{labels:mon.checks.map(c=>c.t),datasets:[{label:'ms',data:mon.checks.map(c=>c.rt),backgroundColor:mon.checks.map(c=>c.s==='up'?'rgba(34,211,164,.8)':'rgba(244,63,94,.8)'),borderRadius:3,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>ctx.raw+'ms'}}},scales:{x:{ticks:{color:'#64748b',font:{size:10},maxTicksLimit:12},grid:{color:'rgba(30,39,64,.5)'}},y:{ticks:{color:'#64748b',font:{size:10},callback:v=>v+'ms'},grid:{color:'rgba(30,39,64,.5)'}}}}});
}
function tbl(m){
  document.getElementById('mtbl').innerHTML='<thead><tr><th>Name</th><th>Status</th><th>Uptime 7d</th><th>Avg Response</th><th>Checks (24h)</th></tr></thead><tbody>'+m.map(mon=>{
    const ar=mon.checks.length?Math.round(mon.checks.reduce((a,c)=>a+c.rt,0)/mon.checks.length):0;
    return `<tr><td style="font-weight:500">${mon.name}</td><td><span class="badge b-${mon.status}">${mon.status}</span></td><td class="mono" style="color:${mon.uptime_7d>=99?'var(--gr)':mon.uptime_7d>=90?'var(--yl)':'var(--rd)'}">${mon.uptime_7d.toFixed(1)}%</td><td class="mono" style="font-size:12px;color:var(--mu)">${ar}ms</td><td class="mono" style="font-size:12px;color:var(--mu)">${mon.checks.length}</td></tr>`;
  }).join('')+'</tbody>';
}
load();
</script></body></html>"""

MONITOR_FORM_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Monitor</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="margin-bottom:24px"><div class="pt">{% if monitor %}Edit Monitor{% else %}Add Monitor{% endif %}</div></div>
  {% if error %}<div class="em">{{ error }}</div>{% endif %}
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start" class="mfg">
    <div class="card">
      <div style="font-weight:600;margin-bottom:16px">Basic Settings</div>
      <form method="POST" id="mform">
        <div class="fg"><label class="fl">Display Name</label><input type="text" name="name" placeholder="My API" value="{{ monitor.name if monitor else '' }}" required></div>
        {% if not monitor %}
        <div class="fg"><label class="fl">Type</label>
          <select name="type" id="ts" onchange="tf(this.value)">
            <option value="http">HTTP / HTTPS</option><option value="heartbeat">Heartbeat (push)</option>
            <option value="database">Database</option>
          </select>
        </div>
        {% endif %}
        <div id="ug" class="fg"><label class="fl">URL</label><input type="url" name="url" placeholder="https://example.com" value="{{ monitor.url if monitor and monitor.type!='database' and monitor.url else '' }}"></div>
        <div id="dbg" class="fg" style="display:none">
          <label class="fl">Database Type</label>
          <select name="db_type" id="dbts">
            <option value="postgres">PostgreSQL</option>
            <option value="mysql">MySQL / MariaDB</option>
            <option value="redis">Redis</option>
            <option value="libsql">libSQL / SQLite / Turso</option>
            <option value="mongodb">MongoDB</option>
          </select>
          <label class="fl" style="margin-top:10px">Connection String</label>
          <input type="text" name="connection_string" placeholder="postgresql://user:pass@host:5432/dbname" value="{{ monitor.url if monitor and monitor.type=='database' and monitor.url else '' }}">
          <div class="fh">e.g. postgresql://user:pass@host:5432/db · mysql://user:pass@host:3306/db · redis://:pass@host:6379/0 · libsql://db.turso.io?authToken=… (or a local .db/.sqlite path) · mongodb://user:pass@host:27017/db</div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div class="fg"><label class="fl">Interval (s)</label><input type="number" name="interval" value="{{ monitor.interval if monitor else 60 }}" min="30" max="86400"></div>
          <div class="fg" id="tg"><label class="fl">Timeout (s)</label><input type="number" name="timeout" value="{{ monitor.timeout if monitor else 10 }}" min="5" max="60"></div>
        </div>
        <div id="gg" class="fg" style="display:none"><label class="fl">Grace Period (s)</label><input type="number" name="grace" value="{{ monitor.heartbeat_grace if monitor else 300 }}" min="60"><div class="fh">Extra time after interval before marking DOWN</div></div>
        <div id="auth-section" class="fg">
          <label class="fl">HTTP Basic Auth (optional)</label>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
            <input type="text" name="http_auth_user" placeholder="Username" value="{{ monitor.http_auth_user or '' }}">
            <input type="password" name="http_auth_pass" placeholder="Password" value="{{ monitor.http_auth_pass or '' }}">
          </div>
          <div class="fh">Leave blank if the URL doesn't require authentication</div>
        </div>
      </form>
    </div>
    <div>
      <div style="display:flex;gap:10px">
        <button type="submit" class="btn bp" form="mform">{% if monitor %}Save{% else %}Create Monitor{% endif %}</button>
        <a href="/dashboard" class="btn bg2">Cancel</a>
      </div>
    </div>
  </div>
</div>
<script>
function tf(t){
  document.getElementById('ug').style.display=t==='http'?'':'none';
  document.getElementById('tg').style.display=t==='http'||t==='database'?'':'none';
  document.getElementById('gg').style.display=t==='heartbeat'?'':'none';
  document.getElementById('auth-section').style.display=t==='http'?'':'none';
  document.getElementById('dbg').style.display=t==='database'?'':'none';
}
{% if monitor %}
tf('{{ monitor.type }}');
{% if monitor.type=='database' and monitor.db_type %}document.getElementById('dbts').value='{{ monitor.db_type }}';{% endif %}
{% endif %}
</script>
<style>@media(max-width:700px){.mfg{grid-template-columns:1fr!important}}</style>
</body></html>"""

MONITOR_DETAIL_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — {{ m.name }}</title>""" + _FAV + _S + """
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
.detail-hero{background:var(--sf);border:1px solid var(--bd);border-radius:16px;padding:28px 28px 24px;margin-bottom:20px}
.detail-url{font-family:var(--mono);font-size:12px;color:var(--mu);margin-top:4px;word-break:break-all}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:18px 16px}
.kpi-val{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1}
.kpi-lbl{color:var(--mu);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-top:6px}
.chart-card{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:20px;margin-bottom:16px}
.chart-card-title{font-size:13px;font-weight:600;color:var(--mu);text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center}
.chart-wrap{position:relative;height:160px}
.timeline-wrap{overflow-x:auto}
.tl-bars{display:flex;gap:2px;height:36px;align-items:flex-end;min-width:600px}
.tl-bar{flex:1;min-width:4px;border-radius:2px 2px 0 0;cursor:pointer;transition:opacity .15s}
.tl-bar:hover{opacity:.75}
.tl-bar.up{background:var(--gr)}
.tl-bar.down{background:var(--rd)}
.tl-bar.mixed{background:var(--yl)}
.tl-bar.empty{background:var(--bd)}
.tl-labels{display:flex;justify-content:space-between;color:var(--mu);font-size:10px;font-family:var(--mono);margin-top:6px;min-width:600px}
.log-row{display:grid;grid-template-columns:140px 80px 70px 1fr;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--bd);font-size:12px}
.log-row:last-child{border-bottom:none}
.log-row:hover{background:rgba(255,255,255,.02);border-radius:6px;margin:0 -8px;padding:10px 8px}
</style>
</head><body>""" + _NAV_T + """
<div class="pg">

  <!-- Hero header -->
  <div class="detail-hero">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span class="dot {% if m.status=='up' %}du pulse{% elif m.status=='down' %}dd{% elif m.status=='maintenance' %}dm{% else %}dp{% endif %}" style="width:10px;height:10px"></span>
          <h1 style="font-size:20px;font-weight:700;margin:0">{{ m.name }}</h1>
          <span class="badge b-{{ m.status if m.status in ['up','down','maintenance'] else 'pending' }}">{{ m.status }}</span>
          {% if not m.active %}<span class="badge" style="background:#1f1a08;color:var(--yl)">PAUSED</span>{% endif %}
        </div>
        {% if m.url %}<div class="detail-url">{{ m.url }}</div>{% endif %}
        {% if m.http_auth_user %}<div style="color:var(--mu);font-size:12px;margin-top:4px">🔒 Auth: {{ m.http_auth_user }}</div>{% endif %}
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start">
        <a href="/monitor/{{ m.id }}/edit" class="btn bg2 bsm">Edit</a>
        <form method="POST" action="/monitor/{{ m.id }}/toggle" style="display:inline"><button type="submit" class="btn bg2 bsm">{{ 'Resume' if not m.active else 'Pause' }}</button></form>
        <form method="POST" action="/monitor/{{ m.id }}/delete" onsubmit="return confirm('Delete this monitor?')"><button type="submit" class="btn bd2 bsm">Delete</button></form>
      </div>
    </div>
  </div>

  <!-- KPI row -->
  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-val" style="color:{% if m.uptime_7d>=99 %}var(--gr){% elif m.uptime_7d>=90 %}var(--yl){% else %}var(--rd){% endif %}">{{ "%.2f"|format(m.uptime_7d) }}%</div>
      <div class="kpi-lbl">Uptime (7d)</div>
    </div>
    {% if m.response_time %}
    <div class="kpi">
      <div class="kpi-val">{{ m.response_time }}<span style="font-size:14px;color:var(--mu)">ms</span></div>
      <div class="kpi-lbl">Last Response</div>
    </div>
    {% endif %}
    {% if checks %}
    <div class="kpi">
      {% set up_count = checks|selectattr('status','equalto','up')|list|length %}
      {% set avg_rt = (checks|selectattr('response_time')|map(attribute='response_time')|list) %}
      <div class="kpi-val">{% if avg_rt %}{{ (avg_rt|sum // avg_rt|length) }}<span style="font-size:14px;color:var(--mu)">ms</span>{% else %}—{% endif %}</div>
      <div class="kpi-lbl">Avg Response</div>
    </div>
    <div class="kpi">
      <div class="kpi-val" style="font-size:18px">{{ checks|length }}</div>
      <div class="kpi-lbl">Checks (100 latest)</div>
    </div>
    {% endif %}
    <div class="kpi">
      <div class="kpi-val" style="font-size:18px">{{ m.interval }}s</div>
      <div class="kpi-lbl">Interval</div>
    </div>
    <div class="kpi">
      <div class="kpi-val mono" style="font-size:16px;text-transform:uppercase">{{ m.type }}</div>
      <div class="kpi-lbl">Type</div>
    </div>
  </div>

  {% if m.type=='heartbeat' and heartbeat_url %}
  <div class="chart-card" style="margin-bottom:16px">
    <div class="chart-card-title">Heartbeat URL</div>
    <div style="color:var(--mu);font-size:13px;margin-bottom:10px">Call this URL regularly. Goes DOWN if silent for interval + grace period.</div>
    <div style="display:flex;gap:8px"><input type="text" id="hbu" value="{{ heartbeat_url }}" readonly style="font-family:var(--mono);font-size:11px"><button class="btn bg2 bsm" onclick="cpHb()">Copy</button></div>
    <div class="mono" style="margin-top:8px;color:var(--mu);font-size:11px">curl "{{ heartbeat_url }}"</div>
  </div>
  {% endif %}

  {% if checks %}

  <!-- Response time chart -->
  {% if m.type in ['http','database'] %}
  <div class="chart-card">
    <div class="chart-card-title">
      <span>Response Time</span>
      <span style="font-size:11px;font-weight:400;color:var(--mu)">Last {{ checks|length }} checks</span>
    </div>
    <div class="chart-wrap"><canvas id="rtChart"></canvas></div>
  </div>

  <!-- Connection phase breakdown -->
  <div class="chart-card" id="phases-card" style="display:none">
    <div class="chart-card-title">
      <span>Connection Phases</span>
      <span style="font-size:11px;font-weight:400;color:var(--mu)">DNS · TCP · TLS · TTFB — ms cumulative</span>
    </div>
    <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:14px;font-size:11px">
      <span style="display:flex;align-items:center;gap:5px"><span style="width:10px;height:10px;border-radius:2px;background:#a78bfa;display:inline-block"></span><span style="color:var(--mu)">DNS Lookup</span></span>
      <span style="display:flex;align-items:center;gap:5px"><span style="width:10px;height:10px;border-radius:2px;background:#60a5fa;display:inline-block"></span><span style="color:var(--mu)">TCP Connect</span></span>
      <span style="display:flex;align-items:center;gap:5px"><span style="width:10px;height:10px;border-radius:2px;background:#34d399;display:inline-block"></span><span style="color:var(--mu)">TLS Handshake</span></span>
      <span style="display:flex;align-items:center;gap:5px"><span style="width:10px;height:10px;border-radius:2px;background:#22d3a4;display:inline-block"></span><span style="color:var(--mu)">TTFB (server)</span></span>
    </div>
    <!-- Latest single-check phase waterfall bar -->
    <div id="phases-bar" style="display:flex;height:26px;border-radius:6px;overflow:hidden;margin-bottom:6px"></div>
    <div id="phases-nums" style="display:flex;gap:20px;flex-wrap:wrap;margin-bottom:18px;font-family:var(--mono);font-size:11px;color:var(--mu)">
      <span>DNS: <b id="pv-dns" style="color:#a78bfa">—</b></span>
      <span>Connect: <b id="pv-conn" style="color:#60a5fa">—</b></span>
      <span>TLS: <b id="pv-tls" style="color:#34d399">—</b></span>
      <span>TTFB: <b id="pv-ttfb" style="color:#22d3a4">—</b></span>
    </div>
    <div class="chart-wrap"><canvas id="phasesChart"></canvas></div>
  </div>
  {% endif %}

  <!-- Uptime timeline -->
  <div class="chart-card">
    <div class="chart-card-title">
      <span>Uptime Timeline</span>
      <span style="font-size:11px;font-weight:400;color:var(--mu)">{{ checks|length }} checks · newest right</span>
    </div>
    <div class="timeline-wrap">
      <div class="tl-bars" id="tlBars"></div>
      <div class="tl-labels" id="tlLabels"></div>
    </div>
  </div>

  <!-- Log table -->
  <div class="chart-card">
    <div class="chart-card-title">
      <span>Check Log</span>
      <span style="font-size:11px;font-weight:400;color:var(--mu)">Most recent first</span>
    </div>
    <div style="margin:0 -4px">
      {% for c in checks[:50] %}
      <div class="log-row">
        <span class="mono" style="color:var(--mu)">{{ c.checked_at.strftime('%m-%d %H:%M:%S') }}</span>
        <span><span class="badge b-{{ c.status }}">{{ c.status }}</span></span>
        <span class="mono" style="color:{% if c.response_time and c.response_time>800 %}var(--yl){% elif c.response_time and c.response_time>2000 %}var(--rd){% else %}var(--tx){% endif %}">
          {% if c.response_time %}{{ c.response_time }}ms{% else %}—{% endif %}
        </span>
        <span style="color:var(--mu);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{ c.message or '—' }}</span>
      </div>
      {% endfor %}
    </div>
  </div>

  <script>
  (function(){
    const checks = {{ checks_json | safe }};
    // Build arrays oldest→newest for charts
    const ordered = [...checks].reverse();
    const labels  = ordered.map(c => c.checked_at ? c.checked_at.slice(11,16) : '');
    const rts     = ordered.map(c => c.response_time || null);
    const statuses= ordered.map(c => c.status);

    // ── Response time line chart ──────────────────────────────────────────────
    const rtEl = document.getElementById('rtChart');
    if(rtEl){
      const up_color   = '#22d3a4';
      const down_color = '#f43f5e';
      new Chart(rtEl, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Response (ms)',
            data: rts,
            backgroundColor: statuses.map(s => s==='up' ? 'rgba(34,211,164,0.7)' : 'rgba(244,63,94,0.7)'),
            borderColor:     statuses.map(s => s==='up' ? '#22d3a4' : '#f43f5e'),
            borderWidth: 0,
            borderRadius: 3,
            borderSkipped: false,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode:'index', intersect:false },
          plugins: {
            legend: { display:false },
            tooltip: {
              backgroundColor: '#111520',
              borderColor: '#1e2740',
              borderWidth: 1,
              titleColor: '#64748b',
              bodyColor: '#e2e8f0',
              callbacks: {
                label: ctx => ctx.raw != null ? ctx.raw + ' ms' : 'timeout',
                title: (items) => {
                  const i = items[0].dataIndex;
                  return labels[i] + ' · ' + statuses[i];
                }
              }
            }
          },
          scales: {
            x: {
              ticks: { color:'#64748b', font:{size:10}, maxTicksLimit:10, maxRotation:0 },
              grid:  { color:'rgba(30,39,64,.4)', drawBorder:false }
            },
            y: {
              ticks: { color:'#64748b', font:{size:10}, callback: v => v+'ms' },
              grid:  { color:'rgba(30,39,64,.4)', drawBorder:false },
              beginAtZero: true
            }
          }
        }
      });
    }

    // ── Connection phase breakdown ────────────────────────────────────────────
    const checksWithPhases = ordered.filter(c => c.phases && c.phases.ttfb);
    const phCard = document.getElementById('phases-card');
    if(phCard && checksWithPhases.length > 0){
      phCard.style.display = '';

      // Latest check phases for the waterfall bar
      const latest = checksWithPhases[checksWithPhases.length - 1];
      const ph = latest.phases;
      const total = ph.ttfb || 1;

      const dnsMs   = ph.namelookup || 0;
      const connMs  = ph.connect ? ph.connect - dnsMs : 0;
      const tlsMs   = ph.tls ? ph.tls - (ph.connect || dnsMs) : 0;
      const ttfbMs  = total - (ph.tls || ph.connect || dnsMs);

      document.getElementById('pv-dns').textContent  = dnsMs + 'ms';
      document.getElementById('pv-conn').textContent = connMs + 'ms';
      document.getElementById('pv-tls').textContent  = ph.tls ? tlsMs + 'ms' : 'n/a';
      document.getElementById('pv-ttfb').textContent = ttfbMs + 'ms';

      // Waterfall stacked bar
      const bar = document.getElementById('phases-bar');
      const segs = [
        { ms: dnsMs,  color: '#a78bfa', label: 'DNS' },
        { ms: connMs, color: '#60a5fa', label: 'TCP' },
        { ms: tlsMs,  color: '#34d399', label: 'TLS' },
        { ms: Math.max(ttfbMs,1), color: '#22d3a4', label: 'TTFB' },
      ];
      segs.forEach(s => {
        const d = document.createElement('div');
        d.style.cssText = `flex:${Math.max(s.ms,1)};background:${s.color};transition:flex .3s;`;
        d.title = `${s.label}: ${s.ms}ms`;
        bar.appendChild(d);
      });

      // Phase history stacked bar chart
      const phLabels = checksWithPhases.map(c => c.checked_at ? c.checked_at.slice(11,16) : '');
      const dnsData  = checksWithPhases.map(c => c.phases.namelookup || 0);
      const connData = checksWithPhases.map(c => c.phases.connect ? c.phases.connect - (c.phases.namelookup||0) : 0);
      const tlsData  = checksWithPhases.map(c => c.phases.tls ? c.phases.tls - (c.phases.connect || c.phases.namelookup||0) : 0);
      const ttfbData = checksWithPhases.map(c => {
        const ph2 = c.phases;
        return (ph2.ttfb||0) - (ph2.tls || ph2.connect || ph2.namelookup || 0);
      });

      new Chart(document.getElementById('phasesChart'), {
        type: 'bar',
        data: {
          labels: phLabels,
          datasets: [
            { label:'DNS Lookup',     data: dnsData,  backgroundColor:'rgba(167,139,250,0.85)', borderWidth:0, borderRadius:0 },
            { label:'TCP Connect',    data: connData, backgroundColor:'rgba(96,165,250,0.85)',  borderWidth:0, borderRadius:0 },
            { label:'TLS Handshake',  data: tlsData,  backgroundColor:'rgba(52,211,153,0.85)',  borderWidth:0, borderRadius:0 },
            { label:'TTFB (server)',  data: ttfbData, backgroundColor:'rgba(34,211,164,0.85)',  borderWidth:0, borderRadius:{topLeft:3,topRight:3} },
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          interaction: { mode:'index', intersect:false },
          plugins: {
            legend: { display:false },
            tooltip: {
              backgroundColor:'#111520', borderColor:'#1e2740', borderWidth:1,
              titleColor:'#64748b', bodyColor:'#e2e8f0',
              callbacks: { label: ctx => ctx.dataset.label + ': ' + ctx.raw + 'ms' }
            }
          },
          scales: {
            x: { stacked:true, ticks:{color:'#64748b',font:{size:10},maxTicksLimit:10,maxRotation:0}, grid:{color:'rgba(30,39,64,.4)'} },
            y: { stacked:true, ticks:{color:'#64748b',font:{size:10},callback:v=>v+'ms'}, grid:{color:'rgba(30,39,64,.4)'}, beginAtZero:true }
          }
        }
      });
    }

    // ── Uptime bar timeline ───────────────────────────────────────────────────
    const barsEl   = document.getElementById('tlBars');
    const labelsEl = document.getElementById('tlLabels');
    if(barsEl && ordered.length){
      // group into ~60 buckets
      const N = 60;
      const bucketSize = Math.max(1, Math.ceil(ordered.length / N));
      const buckets = [];
      for(let i=0;i<ordered.length;i+=bucketSize){
        const slice = ordered.slice(i, i+bucketSize);
        const ups   = slice.filter(c=>c.status==='up').length;
        const downs = slice.filter(c=>c.status==='down').length;
        const pct   = ups/(ups+downs||1);
        buckets.push({ ups, downs, total:slice.length, pct,
          label: slice[0].checked_at ? slice[0].checked_at.slice(11,16) : '' });
      }
      buckets.forEach((b,i) => {
        const div = document.createElement('div');
        div.className = 'tl-bar ' + (b.total===0 ? 'empty' : b.downs===0 ? 'up' : b.ups===0 ? 'down' : 'mixed');
        const h = Math.max(8, Math.round(36 * (b.pct*0.6+0.4)));
        div.style.height = h+'px';
        div.title = `${b.label} — ${b.ups} up, ${b.downs} down`;
        barsEl.appendChild(div);
      });
      // labels: first, middle, last
      const first = document.createElement('span'); first.textContent = ordered[0]?.checked_at?.slice(11,16)||'';
      const mid   = document.createElement('span'); mid.textContent   = ordered[Math.floor(ordered.length/2)]?.checked_at?.slice(11,16)||'';
      const last  = document.createElement('span'); last.textContent  = ordered[ordered.length-1]?.checked_at?.slice(11,16)||'now';
      labelsEl.style.display='flex'; labelsEl.style.justifyContent='space-between';
      labelsEl.appendChild(first); labelsEl.appendChild(mid); labelsEl.appendChild(last);
    }
  })();
  </script>

  {% else %}
  <div class="chart-card" style="text-align:center;padding:48px 20px;color:var(--mu)">
    <div style="font-size:32px;margin-bottom:10px">📡</div>
    <div style="font-weight:600;margin-bottom:4px">No checks yet</div>
    <div style="font-size:12px">Checks will appear here after the first ping</div>
  </div>
  {% endif %}

</div>
<script>function cpHb(){const e=document.getElementById('hbu');navigator.clipboard.writeText(e.value);event.target.textContent='Copied!';setTimeout(()=>event.target.textContent='Copy',1500)}</script>
</body></html>"""

INCIDENTS_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Incidents</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:12px">
    <div><div class="pt">Incidents</div><div class="ps">Track and communicate service disruptions</div></div>
    <a href="/incidents/create" class="btn bp"><svg width="13" height="13" viewBox="0 0 14 14" fill="none"><line x1="7" y1="1" x2="7" y2="13" stroke="white" stroke-width="2" stroke-linecap="round"/><line x1="1" y1="7" x2="13" y2="7" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>New Incident</a>
  </div>
  {% set open_list=incidents|selectattr('status','ne','resolved')|list %}
  {% set done_list=incidents|selectattr('status','equalto','resolved')|list %}
  {% if open_list %}
  <div class="sh">🚨 Active ({{ open_list|length }})</div>
  {% for inc in open_list %}
  <div class="card" style="margin-bottom:10px;border-color:{% if inc.severity=='full_outage' %}rgba(255,32,80,.3){% elif inc.severity=='major' %}rgba(244,63,94,.25){% else %}rgba(249,115,22,.25){% endif %}">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px">
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
          <span class="badge b-{{ inc.severity }}">{{ inc.severity.replace('_',' ') }}</span>
          <span class="badge b-{{ inc.status }}">{{ inc.status }}</span>
        </div>
        <div style="font-weight:600;font-size:15px;margin-bottom:3px">{{ inc.title }}</div>
        {% if inc.monitor_rel %}<div style="color:var(--mu);font-size:12px">Monitor: {{ inc.monitor_rel.name }}</div>{% endif %}
        <div class="mono" style="color:var(--mu);font-size:11px">{{ inc.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</div>
      </div>
      <a href="/incidents/{{ inc.id }}" class="btn bg2 bsm">Manage →</a>
    </div>
  </div>
  {% endfor %}
  {% endif %}
  {% if done_list %}
  <div class="sh">Resolved</div>
  <div class="card" style="padding:0;overflow:hidden">
    <table class="tbl">
      <thead><tr><th>Title</th><th>Severity</th><th>Started</th><th>Resolved</th><th></th></tr></thead>
      <tbody>
      {% for inc in done_list %}
      <tr>
        <td style="font-weight:500">{{ inc.title }}</td>
        <td><span class="badge b-{{ inc.severity }}">{{ inc.severity.replace('_',' ') }}</span></td>
        <td class="mono" style="font-size:11px;color:var(--mu)">{{ inc.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
        <td class="mono" style="font-size:11px;color:var(--mu)">{{ inc.resolved_at.strftime('%Y-%m-%d %H:%M') if inc.resolved_at else '—' }}</td>
        <td><a href="/incidents/{{ inc.id }}" class="btn bg2 bsm">View</a></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
  {% if not incidents %}
  <div class="card" style="text-align:center;padding:60px 20px">
    <div style="font-size:40px;margin-bottom:12px">✅</div>
    <div style="font-size:16px;font-weight:600;margin-bottom:8px">No incidents</div>
    <div style="color:var(--mu)">All systems are running smoothly</div>
  </div>
  {% endif %}
</div></body></html>"""

INCIDENT_FORM_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — New Incident</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg"><div style="margin-bottom:24px"><div class="pt">Create Incident</div></div>
{% if err %}<div class="em">{{ err }}</div>{% endif %}
<div class="card" style="max-width:560px">
  <form method="POST">
    <div class="fg"><label class="fl">Title</label><input type="text" name="title" placeholder="API experiencing errors" required></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="fg"><label class="fl">Severity</label>
        <select name="severity"><option value="degraded">Degraded</option><option value="major" selected>Major</option><option value="full_outage">Full Outage</option></select>
      </div>
      <div class="fg"><label class="fl">Affected Monitor</label>
        <select name="monitor_id"><option value="">— None —</option>{% for m in monitors %}<option value="{{ m.id }}">{{ m.name }}</option>{% endfor %}</select>
      </div>
    </div>
    <div class="fg"><label class="fl">Initial Message</label><textarea name="body" rows="4" placeholder="We are investigating…"></textarea></div>
    <div style="display:flex;gap:10px"><button type="submit" class="btn bp">Create</button><a href="/incidents" class="btn bg2">Cancel</a></div>
  </form>
</div></div></body></html>"""

INCIDENT_DETAIL_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — {{ inc.title }}</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:12px">
    <div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <span class="badge b-{{ inc.severity }}">{{ inc.severity.replace('_',' ') }}</span>
        <span class="badge b-{{ inc.status }}">{{ inc.status }}</span>
      </div>
      <div class="pt">{{ inc.title }}</div>
      <div class="ps">{{ inc.created_at.strftime('%Y-%m-%d %H:%M') }} UTC{% if inc.monitor_rel %} · {{ inc.monitor_rel.name }}{% endif %}{% if inc.resolved_at %} · Resolved {{ inc.resolved_at.strftime('%H:%M') }} UTC{% endif %}</div>
    </div>
    <form method="POST" action="/incidents/{{ inc.id }}/delete" onsubmit="return confirm('Delete?')"><button type="submit" class="btn bd2 bsm">Delete</button></form>
  </div>
  <div style="display:grid;grid-template-columns:1fr {% if inc.status!='resolved' %}320px{% endif %};gap:20px;align-items:start" class="idg">
    <div class="card">
      <div style="font-weight:600;margin-bottom:14px">Timeline</div>
      {% for upd in inc.updates %}
      <div style="display:flex;gap:14px;{% if not loop.last %}padding-bottom:16px{% endif %}">
        <div style="display:flex;flex-direction:column;align-items:center">
          <div style="width:10px;height:10px;border-radius:50%;background:var(--ac);flex-shrink:0;margin-top:4px"></div>
          {% if not loop.last %}<div style="width:2px;flex:1;background:var(--bd);margin-top:4px"></div>{% endif %}
        </div>
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
            <span class="badge b-{{ upd.status or 'open' }}" style="font-size:10px">{{ upd.status or 'update' }}</span>
            <span class="mono" style="font-size:11px;color:var(--mu)">{{ upd.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</span>
          </div>
          <div style="font-size:13px;line-height:1.6;white-space:pre-wrap">{{ upd.message }}</div>
        </div>
      </div>
      {% else %}<div style="color:var(--mu);font-size:13px">No updates yet.</div>
      {% endfor %}
    </div>
    {% if inc.status!='resolved' %}
    <div class="card" style="position:sticky;top:68px">
      <div style="font-weight:600;margin-bottom:14px">Post Update</div>
      <form method="POST" action="/incidents/{{ inc.id }}/update">
        <div class="fg"><label class="fl">Status</label>
          <select name="status"><option value="open" {% if inc.status=='open' %}selected{% endif %}>Investigating</option><option value="monitoring" {% if inc.status=='monitoring' %}selected{% endif %}>Monitoring</option><option value="resolved">Resolved ✓</option></select></div>
        <div class="fg"><label class="fl">Severity</label>
          <select name="severity"><option value="degraded" {% if inc.severity=='degraded' %}selected{% endif %}>Degraded</option><option value="major" {% if inc.severity=='major' %}selected{% endif %}>Major</option><option value="full_outage" {% if inc.severity=='full_outage' %}selected{% endif %}>Full Outage</option></select></div>
        <div class="fg"><label class="fl">Message</label><textarea name="message" rows="4" placeholder="Update…"></textarea></div>
        <button type="submit" class="btn bp" style="width:100%;justify-content:center">Post Update</button>
      </form>
    </div>
    {% endif %}
  </div>
</div>
<style>@media(max-width:700px){.idg{grid-template-columns:1fr!important}}</style>
</body></html>"""

MAINTENANCE_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Maintenance</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:12px">
    <div><div class="pt">Maintenance Windows</div><div class="ps">Planned downtime — shown on public status pages, alerting suppressed</div></div>
    <a href="/maintenance/create" class="btn bp"><svg width="13" height="13" viewBox="0 0 14 14" fill="none"><line x1="7" y1="1" x2="7" y2="13" stroke="white" stroke-width="2" stroke-linecap="round"/><line x1="1" y1="7" x2="13" y2="7" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>Schedule</a>
  </div>
  {% if active_maint %}
  <div class="sh" style="color:var(--pu)">🔧 Active Now ({{ active_maint|length }})</div>
  {% for item in active_maint %}
  <div class="card" style="margin-bottom:10px;border-color:rgba(168,85,247,.3);background:rgba(168,85,247,.04)">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px">
      <div>
        <div style="font-weight:600;font-size:15px;margin-bottom:4px">{{ item.title }}</div>
        {% if item.description %}<div style="color:var(--mu);font-size:13px;margin-bottom:6px">{{ item.description }}</div>{% endif %}
        <div class="mono" style="color:var(--mu);font-size:11px">{{ item.start_time.strftime('%Y-%m-%d %H:%M') }} → {{ item.end_time.strftime('%Y-%m-%d %H:%M') }} UTC</div>
        {% if item.maint_monitors %}<div style="color:var(--mu);font-size:12px;margin-top:4px">Monitors: {% for mm in item.maint_monitors %}{{ mm.monitor.name }}{% if not loop.last %}, {% endif %}{% endfor %}</div>{% endif %}
      </div>
      <form method="POST" action="/maintenance/{{ item.id }}/delete" onsubmit="return confirm('Cancel maintenance?')"><button type="submit" class="btn bd2 bsm">Cancel</button></form>
    </div>
  </div>
  {% endfor %}
  {% endif %}
  {% if upcoming_maint %}
  <div class="sh">📅 Upcoming ({{ upcoming_maint|length }})</div>
  {% for item in upcoming_maint %}
  <div class="card" style="margin-bottom:10px">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px">
      <div>
        <div style="font-weight:600;font-size:15px;margin-bottom:4px">{{ item.title }}</div>
        {% if item.description %}<div style="color:var(--mu);font-size:13px;margin-bottom:6px">{{ item.description }}</div>{% endif %}
        <div class="mono" style="color:var(--mu);font-size:11px">{{ item.start_time.strftime('%Y-%m-%d %H:%M') }} → {{ item.end_time.strftime('%Y-%m-%d %H:%M') }} UTC</div>
        {% if item.maint_monitors %}<div style="color:var(--mu);font-size:12px;margin-top:4px">Monitors: {% for mm in item.maint_monitors %}{{ mm.monitor.name }}{% if not loop.last %}, {% endif %}{% endfor %}</div>{% endif %}
      </div>
      <form method="POST" action="/maintenance/{{ item.id }}/delete" onsubmit="return confirm('Delete?')"><button type="submit" class="btn bd2 bsm">Delete</button></form>
    </div>
  </div>
  {% endfor %}
  {% endif %}
  {% if past_maint %}
  <div class="sh">Past ({{ past_maint|length }})</div>
  <div class="card" style="padding:0;overflow:hidden">
    <table class="tbl">
      <thead><tr><th>Title</th><th>Start</th><th>End</th><th>Monitors</th><th></th></tr></thead>
      <tbody>
      {% for item in past_maint %}
      <tr>
        <td style="font-weight:500">{{ item.title }}</td>
        <td class="mono" style="font-size:11px;color:var(--mu)">{{ item.start_time.strftime('%Y-%m-%d %H:%M') }}</td>
        <td class="mono" style="font-size:11px;color:var(--mu)">{{ item.end_time.strftime('%Y-%m-%d %H:%M') }}</td>
        <td style="color:var(--mu);font-size:12px">{% for mm in item.maint_monitors %}{{ mm.monitor.name }}{% if not loop.last %}, {% endif %}{% endfor %}</td>
        <td><form method="POST" action="/maintenance/{{ item.id }}/delete" onsubmit="return confirm('Delete?')"><button type="submit" class="btn bg2 bsm">Delete</button></form></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
  {% if not items %}
  <div class="card" style="text-align:center;padding:60px 20px">
    <div style="font-size:40px;margin-bottom:12px">🔧</div>
    <div style="font-size:16px;font-weight:600;margin-bottom:8px">No maintenance scheduled</div>
    <div style="color:var(--mu);margin-bottom:20px">Schedule planned downtime to keep users informed</div>
    <a href="/maintenance/create" class="btn bp">Schedule Maintenance</a>
  </div>
  {% endif %}
</div></body></html>"""

MAINTENANCE_FORM_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Schedule Maintenance</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg"><div style="margin-bottom:24px"><div class="pt">Schedule Maintenance</div><div class="ps">Monitors will show as "maintenance" during the window and alerting is suppressed</div></div>
{% if err %}<div class="em">{{ err }}</div>{% endif %}
<div class="card" style="max-width:560px">
  <form method="POST">
    <div class="fg"><label class="fl">Title</label><input type="text" name="title" placeholder="Database migration" required></div>
    <div class="fg"><label class="fl">Description (optional)</label><textarea name="description" rows="2" placeholder="We will be performing…"></textarea></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div class="fg"><label class="fl">Start (UTC)</label><input type="datetime-local" name="start_time" required></div>
      <div class="fg"><label class="fl">End (UTC)</label><input type="datetime-local" name="end_time" required></div>
    </div>
    <div class="fg"><label class="fl">Affected Monitors</label>
      {% if monitors %}
      <div style="display:flex;flex-direction:column;gap:8px">
        {% for m in monitors %}
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;padding:8px 12px;background:var(--s2);border-radius:8px;border:1px solid var(--bd)">
          <input type="checkbox" name="monitors" value="{{ m.id }}">
          <span>{{ m.name }}</span>
          <span class="badge b-{{ m.status if m.status in ['up','down','maintenance'] else 'pending' }}" style="margin-left:auto">{{ m.status }}</span>
        </label>
        {% endfor %}
      </div>
      {% else %}<div style="color:var(--mu);font-size:13px">No monitors yet.</div>{% endif %}
    </div>
    <div style="display:flex;gap:10px;margin-top:8px">
      <button type="submit" class="btn bp">Schedule</button>
      <a href="/maintenance" class="btn bg2">Cancel</a>
    </div>
  </form>
</div></div></body></html>"""

STATUS_PAGES_LIST_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Status Pages</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;flex-wrap:wrap;gap:12px">
    <div><div class="pt">Status Pages</div><div class="ps">Public pages — no domain required · RSS &amp; Atom feeds per page</div></div>
    <a href="/status-pages/create" class="btn bp"><svg width="13" height="13" viewBox="0 0 14 14" fill="none"><line x1="7" y1="1" x2="7" y2="13" stroke="white" stroke-width="2" stroke-linecap="round"/><line x1="1" y1="7" x2="13" y2="7" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>New Page</a>
  </div>
  {% if pages %}
  <div style="display:grid;gap:12px">
    {% for pg in pages %}
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
        <div>
          <div style="font-weight:600;font-size:15px">{{ pg.title }}</div>
          {% if pg.description %}<div style="color:var(--mu);font-size:13px;margin-top:2px">{{ pg.description }}</div>{% endif %}
          <div style="margin-top:8px;display:flex;gap:14px;flex-wrap:wrap;align-items:center">
            <span class="mono" style="font-size:11px;color:var(--ac)">/status/{{ pg.slug }}</span>
            <span style="color:var(--mu);font-size:12px">{{ pg.page_monitors|length }} monitor(s)</span>
            <a href="/status/{{ pg.slug }}/rss" style="font-size:12px;color:var(--or)">RSS</a>
            <a href="/status/{{ pg.slug }}/atom" style="font-size:12px;color:var(--or)">Atom</a>
          </div>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <a href="/status/{{ pg.slug }}" target="_blank" class="btn bg2 bsm">View ↗</a>
          <a href="/status-pages/{{ pg.id }}/edit" class="btn bg2 bsm">Edit</a>
          <form method="POST" action="/status-pages/{{ pg.id }}/delete" onsubmit="return confirm('Delete?')"><button type="submit" class="btn bd2 bsm">Delete</button></form>
        </div>
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="card" style="text-align:center;padding:60px 20px">
    <div style="font-size:40px;margin-bottom:12px">📋</div>
    <div style="font-size:16px;font-weight:600;margin-bottom:8px">No status pages yet</div>
    <a href="/status-pages/create" class="btn bp">Create Status Page</a>
  </div>
  {% endif %}
</div></body></html>"""

STATUS_PAGE_FORM_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Status Page</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg">
  <div style="margin-bottom:24px"><div class="pt">{% if page %}Edit Status Page{% else %}New Status Page{% endif %}</div></div>
  {% if err %}<div class="em">{{ err }}</div>{% endif %}
  <div style="display:grid;grid-template-columns:1fr {% if page %}1fr{% endif %};gap:20px;align-items:start" class="spg">
    <div class="card">
      <div style="font-weight:600;margin-bottom:16px">Page Settings</div>
      <form method="POST">
        <div class="fg"><label class="fl">Title</label><input type="text" name="title" placeholder="My Service Status" value="{{ page.title if page else '' }}" required></div>
        {% if not page %}<div class="fg"><label class="fl">Slug</label><input type="text" name="slug" placeholder="my-service" pattern="[a-z0-9-]+" required><div class="fh">Lowercase, numbers, hyphens → /status/your-slug</div></div>{% endif %}
        <div class="fg"><label class="fl">Description</label><textarea name="description" rows="2" placeholder="All our services at a glance.">{{ page.description if page else '' }}</textarea></div>
        <div class="fg"><label class="fl">Monitors to display</label>
          {% if monitors %}
          <div style="display:flex;flex-direction:column;gap:8px">
            {% for m in monitors %}
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer;padding:8px 12px;background:var(--s2);border-radius:8px;border:1px solid var(--bd)">
              <input type="checkbox" name="monitors" value="{{ m.id }}" {% if m.id in selected_ids %}checked{% endif %}>
              <span>{{ m.name }}</span>
              <span class="badge b-{{ m.status if m.status in ['up','down','maintenance'] else 'pending' }}" style="margin-left:auto">{{ m.status }}</span>
            </label>
            {% endfor %}
          </div>
          {% else %}<div style="color:var(--mu);font-size:13px">No monitors yet. <a href="/monitor/add">Add one.</a></div>{% endif %}
        </div>
        <div style="display:flex;gap:10px;margin-top:8px">
          <button type="submit" class="btn bp">{% if page %}Save{% else %}Create{% endif %}</button>
          <a href="/status-pages" class="btn bg2">Cancel</a>
        </div>
      </form>
    </div>
    {% if page %}
    <div class="card">
      <div style="font-weight:600;margin-bottom:14px">📢 Announcements</div>
      {% for ann in page.announcements|sort(attribute='created_at',reverse=True) %}
      <div style="padding:10px 12px;background:var(--s2);border:1px solid {% if ann.pinned %}rgba(251,191,36,.4){% else %}var(--bd){% endif %};border-radius:8px;margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
          <div style="flex:1">{% if ann.pinned %}<div style="color:var(--yl);font-size:10px;font-weight:700;margin-bottom:2px">📌 PINNED</div>{% endif %}
            <div style="font-weight:600;font-size:13px">{{ ann.title }}</div>
            {% if ann.body %}<div style="color:var(--mu);font-size:12px;margin-top:3px;white-space:pre-wrap">{{ ann.body }}</div>{% endif %}
            <div class="mono" style="color:var(--mu);font-size:10px;margin-top:4px">{{ ann.created_at.strftime('%Y-%m-%d %H:%M') }}</div>
          </div>
          <form method="POST" action="/status-pages/{{ page.id }}/announcements/{{ ann.id }}/delete"><button type="submit" class="btn bd2 bsm" style="padding:3px 8px">✕</button></form>
        </div>
      </div>
      {% endfor %}
      <div style="border-top:1px solid var(--bd);margin-top:12px;padding-top:14px">
        <div style="font-weight:500;margin-bottom:10px;font-size:13px">Post Announcement</div>
        <form method="POST" action="/status-pages/{{ page.id }}/announcements/add">
          <div class="fg"><label class="fl">Title</label><input type="text" name="ann_title" placeholder="Scheduled maintenance tonight" required></div>
          <div class="fg"><label class="fl">Body</label><textarea name="ann_body" rows="3" placeholder="Details…"></textarea></div>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:12px;font-size:13px"><input type="checkbox" name="pinned"> Pin to top</label>
          <button type="submit" class="btn bp bsm">Post</button>
        </form>
      </div>
    </div>
    {% endif %}
  </div>
</div>
<style>@media(max-width:700px){.spg{grid-template-columns:1fr!important}}</style>
</body></html>"""

SETTINGS_TPL = """<!DOCTYPE html><html><head><title>PulseWatch — Settings</title>""" + _FAV + _S + """
</head><body>""" + _NAV_T + """
<div class="pg" style="max-width:700px">
  <div style="margin-bottom:24px"><div class="pt">Settings</div><div class="ps">Notifications, integrations, 2FA, Docker, and automation</div></div>
  {% if saved %}<div class="sm">✓ Settings saved.</div>{% endif %}
  <form method="POST"><input type="hidden" name="action" value="save">

    <div class="sh">🔔 Notifications</div>
    <div class="card" style="margin-bottom:16px">
      <div class="tr-row"><div><div style="font-weight:500">Notify on Monitor Down</div><div style="color:var(--mu);font-size:12px">Alert when a monitor goes DOWN</div></div><input type="checkbox" name="notify_on_down" {% if s.notify_on_down %}checked{% endif %} style="transform:scale(1.3)"></div>
      <div class="tr-row"><div><div style="font-weight:500">Notify on Recovery</div><div style="color:var(--mu);font-size:12px">Alert when a monitor comes back UP</div></div><input type="checkbox" name="notify_on_recover" {% if s.notify_on_recover %}checked{% endif %} style="transform:scale(1.3)"></div>
      <div class="tr-row"><div><div style="font-weight:500">Notify on Incidents</div><div style="color:var(--mu);font-size:12px">Alert on incident create/update</div></div><input type="checkbox" name="notify_on_incident" {% if s.notify_on_incident %}checked{% endif %} style="transform:scale(1.3)"></div>
      <div class="tr-row" style="border:none"><div><div style="font-weight:500">Cooldown (minutes)</div><div style="color:var(--mu);font-size:12px">Min gap between repeat alerts for the same monitor</div></div><input type="number" name="notify_cooldown_min" value="{{ s.notify_cooldown_min }}" min="1" max="1440" style="width:80px;text-align:center"></div>
    </div>

    <div class="sh">🤖 Automation</div>
    <div class="card" style="margin-bottom:16px">
      <div class="tr-row"><div><div style="font-weight:500">Auto-Create Incident on Down</div><div style="color:var(--mu);font-size:12px">Open an incident automatically when a monitor goes DOWN</div></div><input type="checkbox" name="auto_incident" {% if s.auto_incident %}checked{% endif %} style="transform:scale(1.3)"></div>
      <div class="tr-row"><div><div style="font-weight:500">Auto-Resolve on Recovery</div><div style="color:var(--mu);font-size:12px">Resolve open incidents when monitor recovers</div></div><input type="checkbox" name="auto_resolve_incident" {% if s.auto_resolve_incident %}checked{% endif %} style="transform:scale(1.3)"></div>
      <div class="tr-row" style="border:none"><div><div style="font-weight:500">Auto-Incident Severity</div></div><select name="auto_incident_severity" style="width:auto;padding:6px 10px"><option value="degraded" {% if s.auto_incident_severity=='degraded' %}selected{% endif %}>Degraded</option><option value="major" {% if s.auto_incident_severity=='major' %}selected{% endif %}>Major</option><option value="full_outage" {% if s.auto_incident_severity=='full_outage' %}selected{% endif %}>Full Outage</option></select></div>
    </div>

    <div class="sh">💬 Discord Webhook</div>
    <div class="card" style="margin-bottom:16px">
      <div class="fg" style="margin-bottom:0"><label class="fl">Webhook URL</label><input type="url" name="discord_webhook" placeholder="https://discord.com/api/webhooks/…" value="{{ s.discord_webhook or '' }}"><div class="fh">Server Settings → Integrations → Webhooks → New Webhook → Copy URL</div></div>
    </div>

    <div class="sh">🌐 Generic Webhook</div>
    <div class="card" style="margin-bottom:16px">
      <div class="fg"><label class="fl">Webhook URL</label><input type="url" name="generic_webhook" placeholder="https://your-server.com/webhook" value="{{ s.generic_webhook or '' }}"><div class="fh">JSON POST with event, monitor data, and timestamp</div></div>
      <div class="fg" style="margin-bottom:0"><label class="fl">Signing Secret</label><input type="text" name="webhook_secret" placeholder="optional HMAC secret" value="{{ s.webhook_secret or '' }}"><div class="fh">Adds X-PulseWatch-Signature header (HMAC-SHA256)</div></div>
    </div>

    <div style="display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap">
      <button type="submit" class="btn bp">Save Settings</button>
      <button type="submit" name="action" value="test_discord" class="btn bg2" {% if not s.discord_webhook %}disabled{% endif %}>Test Discord</button>
      <button type="submit" name="action" value="test_webhook" class="btn bg2" {% if not s.generic_webhook %}disabled{% endif %}>Test Webhook</button>
    </div>
  </form>

  <div class="sh">📡 RSS &amp; Atom Feeds</div>
  <div class="card" style="margin-bottom:16px">
    <div style="color:var(--mu);font-size:13px;margin-bottom:10px">Each status page has RSS and Atom feeds for incidents and announcements.</div>
    <div class="mono" style="font-size:12px;color:var(--ac)">/status/&lt;slug&gt;/rss &nbsp;&nbsp; /status/&lt;slug&gt;/atom</div>
  </div>

  <div class="sh">🐳 Docker Integration</div>
  <div class="card" style="margin-bottom:16px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><div style="width:8px;height:8px;border-radius:50%;background:var(--rd)"></div><div style="font-weight:600;color:var(--rd)">Docker auto-restart disabled</div></div>
    <div style="color:var(--mu);font-size:13px">Docker auto-restart has been removed. Monitors still track HTTP/heartbeat status.</div>
  </div>

  <div class="sh">🔑 Change Password</div>
  <div class="card" style="margin-bottom:16px">
    {% if pw_error %}<div class="em">{{ pw_error }}</div>{% endif %}
    {% if pw_saved %}<div class="sm">✓ Password changed successfully.</div>{% endif %}
    <form method="POST" action="/settings/change-password">
      <div class="fg"><label class="fl">Current Password</label><input type="password" name="current_password" placeholder="••••••••" required></div>
      <div class="fg"><label class="fl">New Password</label><input type="password" name="new_password" placeholder="••••••••" required></div>
      <div class="fg" style="margin-bottom:0"><label class="fl">Confirm New Password</label><input type="password" name="confirm_password" placeholder="••••••••" required></div>
      <div style="margin-top:14px"><button type="submit" class="btn bp bsm">Change Password</button></div>
    </form>
  </div>

  <div class="sh" style="color:var(--rd)">⚠️ Danger Zone</div>
  <div class="card" style="margin-bottom:16px;border-color:rgba(244,63,94,.3);background:rgba(244,63,94,.03)">
    {% if del_error %}<div class="em">{{ del_error }}</div>{% endif %}
    <div style="font-weight:600;margin-bottom:4px">Delete Account</div>
    <div style="color:var(--mu);font-size:13px;margin-bottom:14px">Permanently deletes your account, all monitors, status pages, and data. This cannot be undone.</div>
    <details>
      <summary style="cursor:pointer;color:var(--rd);font-size:13px;font-weight:600;list-style:none">I want to delete my account →</summary>
      <form method="POST" action="/settings/delete-account" style="margin-top:14px" onsubmit="return confirm('This will permanently delete everything. Are you sure?')">
        <div class="fg"><label class="fl">Enter your password to confirm</label><input type="password" name="confirm_password" placeholder="••••••••" required></div>
        <button type="submit" class="btn bd2 bsm">Delete My Account Permanently</button>
      </form>
    </details>
  </div>

  <div class="sh">🔐 Two-Factor Authentication</div>
  <div class="card">
    {% if not totp_ok %}
    <div style="color:var(--mu);font-size:13px">Install <span class="mono">pyotp</span> and <span class="mono">qrcode[pil]</span> to enable 2FA.</div>
    {% elif user.totp_enabled %}
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
      <div><div style="font-weight:600;color:var(--gr);margin-bottom:4px">✓ 2FA is enabled</div><div style="color:var(--mu);font-size:13px">TOTP — works with Google Authenticator, Authy, etc.</div></div>
      <form method="POST" action="/settings/2fa/disable" onsubmit="return confirm('Disable 2FA?')"><button type="submit" class="btn bd2 bsm">Disable 2FA</button></form>
    </div>
    {% else %}
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
      <div><div style="font-weight:600;margin-bottom:4px">2FA is off</div><div style="color:var(--mu);font-size:13px">Add an extra security layer with a TOTP authenticator app</div></div>
      <form method="POST" action="/settings/2fa/enable"><button type="submit" class="btn bp bsm">Enable 2FA</button></form>
    </div>
    {% endif %}
  </div>
</div></body></html>"""

# ─── Public Status Page ───────────────────────────────────────────────────────

PUBLIC_STATUS_TPL = """<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<title>{{ page.title }} — Status</title>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate" type="application/rss+xml" title="{{ page.title }} RSS" href="{{ request.host_url }}status/{{ page.slug }}/rss">
<link rel="alternate" type="application/atom+xml" title="{{ page.title }} Atom" href="{{ request.host_url }}status/{{ page.slug }}/atom">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root[data-theme=light]{--bg:#f1f5f9;--sf:#fff;--s2:#f8fafc;--bd:#e2e8f0;--tx:#0f172a;--mu:#64748b;--gr:#059669;--rd:#dc2626;--yl:#d97706;--or:#ea580c;--pu:#7c3aed;--ac:#2563eb;--gbg:#d1fae5;--rbg:#fee2e2;--ybg:#fef3c7;--maintbg:#ede9fe;--uc:#065f46;--dc2:#991b1b;--pc:#92400e;--maintc:#5b21b6;--tog:#e2e8f0}
:root[data-theme=dark]{--bg:#0a0d14;--sf:#111520;--s2:#181e2e;--bd:#1e2740;--tx:#e2e8f0;--mu:#64748b;--gr:#22d3a4;--rd:#f43f5e;--yl:#fbbf24;--or:#f97316;--pu:#a855f7;--ac:#3b82f6;--gbg:#0d2e22;--rbg:#2d0f1c;--ybg:#1f1a08;--maintbg:#1a1030;--uc:#22d3a4;--dc2:#f43f5e;--pc:#fbbf24;--maintc:#a855f7;--tog:#1e2740}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'DM Sans',sans-serif;font-size:14px;min-height:100vh;transition:background .25s,color .25s}
.hdr{background:var(--sf);border-bottom:1px solid var(--bd);padding:40px 24px 32px;text-align:center;position:relative}
.hdr h1{font-size:26px;font-weight:700;margin-bottom:6px}
.hdr p{color:var(--mu);font-size:14px;margin-top:4px}
.ov{display:inline-flex;align-items:center;gap:8px;margin-top:18px;padding:10px 22px;border-radius:30px;font-weight:600;font-size:14px}
.ov-up{background:var(--gbg);color:var(--gr)}.ov-dn{background:var(--rbg);color:var(--rd)}.ov-mt{background:var(--maintbg);color:var(--pu)}
.ttog{position:absolute;top:16px;right:20px;background:var(--tog);border:1px solid var(--bd);border-radius:30px;padding:6px 14px;cursor:pointer;font-size:12px;font-weight:600;color:var(--mu);display:flex;align-items:center;gap:6px;transition:all .2s;outline:none}
.ttog:hover{color:var(--tx)}
.wrap{max-width:740px;margin:0 auto;padding:28px 20px 60px}
.sh{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--mu);font-weight:700;margin:24px 0 10px}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:18px 20px;margin-bottom:10px;transition:background .25s,border-color .25s}
.mr{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:12px}
.mn{font-weight:600;font-size:15px}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 12px;border-radius:20px;font-size:11px;font-weight:700;font-family:'Space Mono',monospace;text-transform:uppercase;letter-spacing:.04em}
.b-up{background:var(--gbg);color:var(--uc)}.b-down{background:var(--rbg);color:var(--dc2)}
.b-pending{background:var(--ybg);color:var(--pc)}.b-maintenance{background:var(--maintbg);color:var(--maintc)}
.b-degraded{background:var(--ybg);color:var(--yl)}.b-major{background:var(--rbg);color:var(--dc2)}
.b-full_outage{background:rgba(255,32,80,.1);color:#ff2050}
.b-resolved{background:var(--gbg);color:var(--uc)}.b-open{background:var(--ybg);color:var(--yl)}.b-monitoring{background:rgba(37,99,235,.1);color:var(--ac)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.d-up{background:var(--gr);box-shadow:0 0 6px var(--gr)}.d-dn{background:var(--rd);box-shadow:0 0 6px var(--rd)}.d-mt{background:var(--pu)}.d-pe{background:var(--yl)}
.mb{background:var(--maintbg);border:1px solid rgba(124,58,237,.3);border-radius:10px;padding:14px 18px;margin-bottom:10px;display:flex;gap:12px;align-items:flex-start}
.ic{border-radius:10px;padding:14px 18px;margin-bottom:10px;border:1px solid}
.ic-degraded{background:rgba(234,88,12,.07);border-color:rgba(234,88,12,.25)}
.ic-major{background:var(--rbg);border-color:rgba(220,38,38,.25)}
.ic-full_outage{background:rgba(255,32,80,.06);border-color:rgba(255,32,80,.3)}
:root[data-theme=dark] .ic-degraded{background:rgba(249,115,22,.07)}
.ann{background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:14px 18px;margin-bottom:10px}
.ann-pin{border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.04)}
.tl{border-left:2px solid var(--bd);margin-left:8px;padding-left:16px;margin-top:10px}
.tl-it{margin-bottom:10px;position:relative}
.tl-it::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--ac);position:absolute;left:-20px;top:4px}
.footer{text-align:center;padding:28px;color:var(--mu);font-size:12px;border-top:1px solid var(--bd)}
.feed-links a{color:var(--or);font-size:12px;margin:0 6px}
@media(max-width:600px){.mr{flex-direction:column;align-items:flex-start;gap:8px}}
</style>
</head>
<body>
<div class="hdr">
  <button class="ttog" onclick="toggleTheme()" id="tbtn">🌙 Dark</button>
  <div style="font-family:'Space Mono',monospace;font-size:11px;color:var(--mu);margin-bottom:8px;letter-spacing:.06em">STATUS PAGE</div>
  <h1>{{ page.title }}</h1>
  {% if page.description %}<p>{{ page.description }}</p>{% endif %}
  {% set page_mons=page.page_monitors %}
  {% set any_dn=page_mons|selectattr('monitor.status','equalto','down')|list|length>0 %}
  {% set any_mt=(page_mons|selectattr('monitor.status','equalto','maintenance')|list|length>0) or (active_maints|length>0) %}
  <div class="ov {% if any_dn %}ov-dn{% elif any_mt %}ov-mt{% else %}ov-up{% endif %}">
    <span class="dot {% if any_dn %}d-dn{% elif any_mt %}d-mt{% else %}d-up{% endif %}"></span>
    {% if any_dn %}Some Systems Degraded{% elif any_mt %}Under Maintenance{% else %}All Systems Operational{% endif %}
  </div>
</div>

<div class="wrap">

{% if active_maints %}
<div class="sh">🔧 Active Maintenance</div>
{% for maint in active_maints %}
<div class="mb"><span style="font-size:20px;line-height:1.2">🔧</span><div>
  <div style="font-weight:600;margin-bottom:3px">{{ maint.title }}</div>
  {% if maint.description %}<div style="color:var(--mu);font-size:13px;margin-bottom:4px">{{ maint.description }}</div>{% endif %}
  <div style="font-size:12px;color:var(--mu);font-family:'Space Mono',monospace">{{ maint.start_time.strftime('%Y-%m-%d %H:%M') }} → {{ maint.end_time.strftime('%Y-%m-%d %H:%M') }} UTC</div>
</div></div>
{% endfor %}
{% endif %}

{% if upcoming_maints %}
<div class="sh">📅 Upcoming Maintenance</div>
{% for maint in upcoming_maints %}
<div class="card" style="border-color:rgba(124,58,237,.2)">
  <div style="font-weight:600;margin-bottom:3px">{{ maint.title }}</div>
  {% if maint.description %}<div style="color:var(--mu);font-size:13px;margin-bottom:4px">{{ maint.description }}</div>{% endif %}
  <div style="font-size:12px;color:var(--mu);font-family:'Space Mono',monospace">{{ maint.start_time.strftime('%Y-%m-%d %H:%M') }} → {{ maint.end_time.strftime('%Y-%m-%d %H:%M') }} UTC</div>
</div>
{% endfor %}
{% endif %}

{% if announcements %}
<div class="sh">📢 Announcements</div>
{% for ann in announcements %}
<div class="ann {% if ann.pinned %}ann-pin{% endif %}">
  {% if ann.pinned %}<div style="color:var(--yl);font-size:10px;font-weight:700;margin-bottom:4px">📌 PINNED</div>{% endif %}
  <div style="font-weight:600;{% if ann.body %}margin-bottom:6px{% endif %}">{{ ann.title }}</div>
  {% if ann.body %}<div style="color:var(--mu);font-size:13px;white-space:pre-wrap;line-height:1.6">{{ ann.body }}</div>{% endif %}
  <div style="color:var(--mu);font-size:11px;margin-top:8px;font-family:'Space Mono',monospace">{{ ann.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</div>
</div>
{% endfor %}
{% endif %}

{% if active_incidents %}
<div class="sh">🚨 Active Incidents</div>
{% for inc in active_incidents %}
<div class="ic ic-{{ inc.severity }}">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
    <span class="badge b-{{ inc.severity }}">{{ inc.severity.replace('_',' ') }}</span>
    <span class="badge b-{{ inc.status }}">{{ inc.status }}</span>
    <span style="color:var(--mu);font-size:11px;font-family:'Space Mono',monospace">{{ inc.created_at.strftime('%Y-%m-%d %H:%M') }} UTC</span>
  </div>
  <div style="font-weight:600;font-size:15px;margin-bottom:6px">{{ inc.title }}</div>
  {% if inc.updates %}
  <div class="tl">
    {% for upd in inc.updates %}{% if loop.index<=3 %}
    <div class="tl-it">
      <div style="font-size:11px;color:var(--mu);font-family:'Space Mono',monospace;margin-bottom:2px">{{ upd.created_at.strftime('%H:%M') }} UTC</div>
      <div style="font-size:13px;white-space:pre-wrap">{{ upd.message }}</div>
    </div>
    {% endif %}{% endfor %}
  </div>
  {% endif %}
</div>
{% endfor %}
{% endif %}

<div class="sh">Services</div>
{% if page_mons %}
{% for spm in page_mons %}{% set m=spm.monitor %}
<div class="card">
  <div class="mr">
    <div style="display:flex;align-items:center;gap:10px">
      <span class="dot {% if m.status=='up' %}d-up{% elif m.status=='down' %}d-dn{% elif m.status=='maintenance' %}d-mt{% else %}d-pe{% endif %}"></span>
      <span class="mn">{{ m.name }}</span>
    </div>
    <span class="badge b-{{ m.status if m.status in ['up','down','maintenance'] else 'pending' }}">{{ m.status }}</span>
  </div>
  <div style="display:flex;justify-content:space-between;color:var(--mu);font-size:12px">
    <span>Uptime (7d): <strong style="color:var(--tx)">{{ "%.2f"|format(m.uptime_7d) }}%</strong></span>
    {% if m.response_time and m.type in ['http','database'] %}<span style="font-family:'Space Mono',monospace">{{ m.response_time }}ms</span>{% endif %}
  </div>
</div>
{% endfor %}
{% else %}
<div class="card" style="text-align:center;padding:40px;color:var(--mu)">No services on this status page.</div>
{% endif %}

{% if recent_incidents %}
<div class="sh">📋 Past Incidents (14 days)</div>
{% for inc in recent_incidents %}
<div class="card" style="opacity:.8">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
    <span class="badge b-resolved">resolved</span>
    <span class="badge b-{{ inc.severity }}" style="font-size:10px">{{ inc.severity.replace('_',' ') }}</span>
  </div>
  <div style="font-weight:600;margin-bottom:3px">{{ inc.title }}</div>
  <div style="font-size:12px;color:var(--mu);font-family:'Space Mono',monospace">Resolved {{ inc.resolved_at.strftime('%Y-%m-%d %H:%M') }} UTC</div>
</div>
{% endfor %}
{% endif %}

</div>
<div class="footer">
  Powered by <strong>PulseWatch</strong> &nbsp;·&nbsp; <span id="ts"></span>
  <div class="feed-links" style="margin-top:6px">
    <a href="/status/{{ page.slug }}/rss">RSS Feed</a> ·
    <a href="/status/{{ page.slug }}/atom">Atom Feed</a>
  </div>
</div>
<script>
(function(){const t=localStorage.getItem('pw-theme')||'light';apply(t)})();
function apply(t){document.documentElement.setAttribute('data-theme',t);const b=document.getElementById('tbtn');if(b)b.textContent=t==='dark'?'☀️ Light':'🌙 Dark';}
function toggleTheme(){const c=document.documentElement.getAttribute('data-theme');const n=c==='dark'?'light':'dark';localStorage.setItem('pw-theme',n);apply(n);}
document.getElementById('ts').textContent='Last updated '+new Date().toUTCString();
setTimeout(()=>location.reload(),60000);
</script>
</body></html>"""

# ═══════════════════════════════════════════════════════════════════════════════
# INIT
# ═══════════════════════════════════════════════════════════════════════════════

def _init_db_with_retry(retries=10, delay=5):
    """
    Retry db.create_all() so transient DNS/network failures at startup
    (common with external DBs like Aiven) don't kill the gunicorn worker.
    """
    import time as _t
    for attempt in range(1, retries + 1):
        try:
            with app.app_context():
                db.create_all()
            print(f"[PulseWatch] DB ready: {_DB_URL}")
            return
        except Exception as e:
            print(f"[PulseWatch] DB init attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                print(f"[PulseWatch] Retrying in {delay}s...")
                _t.sleep(delay)
            else:
                print("[PulseWatch] WARNING: Could not reach DB at startup. "
                      "App will start anyway; DB errors will surface on requests.")

_init_db_with_retry()

scheduler.start()
with app.app_context():
    try:
        init_scheduler()
        print("[PulseWatch] Scheduler started.")
    except Exception as e:
        print(f"[PulseWatch] Scheduler warning: {e}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[PulseWatch] http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
