#!/usr/bin/env python3
import hashlib, hmac, html, ipaddress, os, re, secrets, sqlite3, time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA_DIR = Path(os.environ.get("ROUTE_PORTAL_DATA", "/var/lib/route-portal"))
DB_PATH = DATA_DIR / "portal.db"
PUBLIC_DIR = DATA_DIR / "public"
LISTEN = os.environ.get("ROUTE_PORTAL_LISTEN", "127.0.0.1")
PORT = int(os.environ.get("ROUTE_PORTAL_PORT", "8080"))
LOGO_PATH = Path(os.environ.get("ROUTE_PORTAL_LOGO", "/opt/route-portal/logo.svg"))
SESSION_TTL, MAX_BODY = 12 * 3600, 2 * 1024 * 1024


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def password_ok(password, encoded):
    try:
        _, rounds, salt, expected = encoded.split("$")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def normalize_list(raw):
    tokens = []
    for line in raw.replace(",", "\n").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            tokens.extend(line.split())
    networks, errors = [], []
    for token in tokens:
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            errors.append(f"{token}: {exc}")
    if errors:
        raise ValueError("\n".join(errors[:30]))
    collapsed = list(ipaddress.collapse_addresses(networks))
    text = "\n".join(str(item) for item in collapsed) + ("\n" if collapsed else "")
    return text, len(tokens), len(collapsed)


def slugify(value):
    value = value.lower().strip()
    if not value or len(value) > 40 or not re.fullmatch(r"[a-z0-9_-]+", value):
        raise ValueError("РРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ РґРѕР»Р¶РµРЅ СЃРѕРґРµСЂР¶Р°С‚СЊ 1вЂ“40 СЃРёРјРІРѕР»РѕРІ: a-z, 0-9, _ РёР»Рё -")
    return value


def export_path(slug):
    return PUBLIC_DIR / f"{slug}.txt"


def init():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS versions(id INTEGER PRIMARY KEY AUTOINCREMENT,created INTEGER NOT NULL,username TEXT NOT NULL,source_count INTEGER NOT NULL,output_count INTEGER NOT NULL,content TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS managed_lists(
          id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,slug TEXT NOT NULL UNIQUE,
          description TEXT NOT NULL DEFAULT '',export_token TEXT NOT NULL UNIQUE,
          content TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL,updated INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS list_versions(
          id INTEGER PRIMARY KEY AUTOINCREMENT,list_id INTEGER NOT NULL REFERENCES managed_lists(id) ON DELETE CASCADE,
          created INTEGER NOT NULL,username TEXT NOT NULL,source_count INTEGER NOT NULL,output_count INTEGER NOT NULL,content TEXT NOT NULL);
        """)
        if not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            user, password = os.environ.get("ROUTE_PORTAL_ADMIN_USER", "admin"), os.environ.get("ROUTE_PORTAL_ADMIN_PASSWORD")
            if not password or len(password) < 12:
                raise SystemExit("Set ROUTE_PORTAL_ADMIN_PASSWORD to at least 12 characters")
            c.execute("INSERT INTO users VALUES(?,?)", (user, password_hash(password)))
        if not c.execute("SELECT 1 FROM managed_lists WHERE slug='routes'").fetchone():
            legacy = PUBLIC_DIR / "routes.txt"
            content = legacy.read_text(encoding="ascii") if legacy.exists() else ""
            row = c.execute("SELECT value FROM settings WHERE key='export_token'").fetchone()
            token = row[0] if row else secrets.token_urlsafe(32)
            now = int(time.time())
            c.execute("""INSERT INTO managed_lists(title,slug,description,export_token,content,created,updated)
                         VALUES(?,?,?,?,?,?,?)""",
                      ("РњР°СЂС€СЂСѓС‚С‹ С‡РµСЂРµР· Amnezia", "routes", "РЎРµС‚Рё РґР»СЏ ROUTE_VIA_AMNEZIA", token, content, now, now))
        if not c.execute("SELECT 1 FROM managed_lists WHERE slug='bypass'").fetchone():
            now = int(time.time())
            c.execute("""INSERT INTO managed_lists(title,slug,description,export_token,content,created,updated)
                         VALUES(?,?,?,?,?,?,?)""",
                      ("РСЃРєР»СЋС‡РµРЅРёСЏ", "bypass", "РљР»РёРµРЅС‚С‹, РєРѕС‚РѕСЂС‹Рµ РѕР±С…РѕРґСЏС‚ РјР°СЂС€СЂСѓС‚С‹ Amnezia", secrets.token_urlsafe(32), "", now, now))
        for item in c.execute("SELECT slug,content FROM managed_lists"):
            export_path(item["slug"]).write_text(item["content"], encoding="ascii")


STYLE = """
body{font-family:system-ui,sans-serif;background:#f4f6f8;color:#17202a;margin:0}main{max-width:1050px;margin:35px auto;padding:0 20px}
.card{background:#fff;border:1px solid #dce2e8;border-radius:12px;padding:22px;box-shadow:0 5px 20px #23303f12;margin:14px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}.row{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
h1,h2{margin-top:0}textarea,input{box-sizing:border-box;width:100%;padding:11px;border:1px solid #adb8c4;border-radius:7px}
textarea{min-height:440px;font:13px ui-monospace,monospace}button,.button{display:inline-block;background:#1769e0;color:#fff;border:0;border-radius:7px;padding:10px 16px;text-decoration:none;cursor:pointer}
.secondary{background:#596775}.danger{background:#bd2c2c}.muted{color:#66717d;font-size:14px}.notice{padding:10px;border-radius:7px;background:#e9f6ec}.error{background:#fdecec;white-space:pre-wrap}
code{word-break:break-all}.actions{display:flex;gap:8px;align-items:center}.inline{display:inline}
.brand{display:flex;align-items:center;gap:14px}.logo{width:64px;height:58px;object-fit:contain}.brand h1{margin:0}
"""


def page(title, body):
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>""".encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "RoutePortal/2.0"
    def end_headers(self):
        for k, v in [("X-Content-Type-Options","nosniff"),("X-Frame-Options","DENY"),("Referrer-Policy","no-referrer"),
                     ("Content-Security-Policy","default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")]:
            self.send_header(k, v)
        super().end_headers()
    def respond(self, status, body, content_type="text/html; charset=utf-8", extra=()):
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body)))
        for k, v in extra: self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def redirect(self, location, cookie=None):
        headers = [("Location", location)] + ([("Set-Cookie", cookie)] if cookie else [])
        self.respond(303, b"", extra=headers)
    def form(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY: raise ValueError("Request is too large")
        return {k: v[-1] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
    def session(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", "")); token = jar.get("rp_session")
        if not token: return None
        with db() as c:
            c.execute("DELETE FROM sessions WHERE expires<?", (int(time.time()),))
            return c.execute("SELECT username,csrf FROM sessions WHERE token_hash=?",
                             (hashlib.sha256(token.value.encode()).hexdigest(),)).fetchone()
    def require_session(self):
        session = self.session()
        if not session: self.redirect("/login")
        return session
    def list_by_id(self, list_id):
        with db() as c: return c.execute("SELECT * FROM managed_lists WHERE id=?", (list_id,)).fetchone()
    def csrf_ok(self, data, session):
        return hmac.compare_digest(data.get("csrf", ""), session["csrf"])

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health": return self.respond(200, b"ok\n", "text/plain")
        if parsed.path == "/logo.svg" and LOGO_PATH.exists():
            return self.respond(200, LOGO_PATH.read_bytes(), "image/svg+xml", [("Cache-Control","public, max-age=3600")])
        match = re.fullmatch(r"/lists/([a-z0-9_-]+)\.txt", parsed.path)
        if match:
            with db() as c: item = c.execute("SELECT * FROM managed_lists WHERE slug=?", (match.group(1),)).fetchone()
            supplied = parse_qs(parsed.query).get("token", [""])[0]
            if not item or not hmac.compare_digest(supplied, item["export_token"]): return self.respond(404, b"not found\n", "text/plain")
            return self.respond(200, item["content"].encode("ascii"), "text/plain; charset=ascii", [("Cache-Control","no-store")])
        if parsed.path == "/login":
            return self.respond(200, page("Р’С…РѕРґ", """<div class="card"><div class="brand"><img class="logo" src="/logo.svg" alt=""><h1>Route Portal</h1></div><form method="post" action="/login">
            <p><label>Р›РѕРіРёРЅ<input name="username" required></label></p><p><label>РџР°СЂРѕР»СЊ<input type="password" name="password" required></label></p><button>Р’РѕР№С‚Рё</button></form></div>"""))
        session = self.require_session()
        if not session: return
        if parsed.path == "/":
            with db() as c: items = c.execute("""SELECT m.*,COUNT(v.id) version_count FROM managed_lists m
                                                LEFT JOIN list_versions v ON v.list_id=m.id GROUP BY m.id ORDER BY m.title""").fetchall()
            cards = "".join(f"""<div class="card"><h2>{html.escape(x['title'])}</h2><p>{html.escape(x['description'])}</p>
            <p class="muted">{len(x['content'].splitlines())} СЃРµС‚РµР№ В· РІРµСЂСЃРёР№: {x['version_count']}</p>
            <a class="button" href="/edit/{x['id']}">РћС‚РєСЂС‹С‚СЊ</a></div>""" for x in items)
            body = f"""<div class="row"><div class="brand"><img class="logo" src="/logo.svg" alt=""><h1>РЎРїРёСЃРєРё pfSense</h1></div><div class="actions"><a class="button" href="/new">РќРѕРІС‹Р№ СЃРїРёСЃРѕРє</a>
            <form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{session['csrf']}"><button class="secondary">Р’С‹Р№С‚Рё</button></form></div></div><div class="grid">{cards}</div>"""
            return self.respond(200, page("РЎРїРёСЃРєРё pfSense", body))
        if parsed.path == "/new":
            body = f"""<div class="card"><div class="brand"><img class="logo" src="/logo.svg" alt=""><h1>РќРѕРІС‹Р№ СЃРїРёСЃРѕРє</h1></div><form method="post" action="/new"><input type="hidden" name="csrf" value="{session['csrf']}">
            <p><label>РќР°Р·РІР°РЅРёРµ<input name="title" required></label></p><p><label>РРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ РґР»СЏ URL<input name="slug" placeholder="example-list" required></label></p>
            <p><label>РћРїРёСЃР°РЅРёРµ<input name="description"></label></p><button>РЎРѕР·РґР°С‚СЊ</button> <a class="button secondary" href="/">РћС‚РјРµРЅР°</a></form></div>"""
            return self.respond(200, page("РќРѕРІС‹Р№ СЃРїРёСЃРѕРє", body))
        match = re.fullmatch(r"/edit/(\d+)", parsed.path)
        if match:
            item = self.list_by_id(int(match.group(1)))
            if not item: return self.respond(404, b"not found\n", "text/plain")
            url = f"http://{self.headers.get('Host','SERVER')}/lists/{item['slug']}.txt?token={item['export_token']}"
            body = f"""<div class="row"><div class="brand"><img class="logo" src="/logo.svg" alt=""><h1>{html.escape(item['title'])}</h1></div><a class="button secondary" href="/">Рљ СЃРїРёСЃРєР°Рј</a></div>
            <div class="card"><form method="post" action="/save/{item['id']}"><input type="hidden" name="csrf" value="{session['csrf']}">
            <p><label>РќР°Р·РІР°РЅРёРµ<input name="title" value="{html.escape(item['title'])}" required></label></p>
            <p><label>РћРїРёСЃР°РЅРёРµ<input name="description" value="{html.escape(item['description'])}"></label></p>
            <textarea name="networks" spellcheck="false">{html.escape(item['content'])}</textarea><p><button>РџСЂРѕРІРµСЂРёС‚СЊ Рё РѕРїСѓР±Р»РёРєРѕРІР°С‚СЊ</button></p></form>
            <p class="muted">URL РґР»СЏ pfSense URL Table Alias:</p><code>{html.escape(url)}</code><hr>
            <form method="post" action="/delete/{item['id']}" onsubmit="return confirm('РЈРґР°Р»РёС‚СЊ СЃРїРёСЃРѕРє?')"><input type="hidden" name="csrf" value="{session['csrf']}">
            <button class="danger">РЈРґР°Р»РёС‚СЊ СЃРїРёСЃРѕРє</button></form></div>"""
            return self.respond(200, page(item["title"], body))
        return self.respond(404, b"not found\n", "text/plain")

    def do_POST(self):
        if self.path == "/login":
            data = self.form()
            with db() as c:
                user = c.execute("SELECT * FROM users WHERE username=?", (data.get("username",""),)).fetchone()
                if not user or not password_ok(data.get("password",""), user["password_hash"]):
                    time.sleep(1); return self.respond(401, page("РћС€РёР±РєР°", '<div class="card"><div class="notice error">РќРµРІРµСЂРЅС‹Р№ Р»РѕРіРёРЅ РёР»Рё РїР°СЂРѕР»СЊ.</div><a class="button" href="/login">РќР°Р·Р°Рґ</a></div>'))
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
                c.execute("INSERT INTO sessions VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["username"], csrf, int(time.time())+SESSION_TTL))
            return self.redirect("/", f"rp_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")
        session = self.require_session()
        if not session: return
        data = self.form()
        if not self.csrf_ok(data, session): return self.respond(403, b"invalid csrf\n", "text/plain")
        if self.path == "/logout":
            jar = cookies.SimpleCookie(self.headers.get("Cookie",""))
            if jar.get("rp_session"):
                with db() as c: c.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(jar["rp_session"].value.encode()).hexdigest(),))
            return self.redirect("/login", "rp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        if self.path == "/new":
            try: slug = slugify(data.get("slug",""))
            except ValueError as exc: return self.respond(400, page("РћС€РёР±РєР°", f'<div class="card"><div class="notice error">{html.escape(str(exc))}</div><a class="button" href="/new">РќР°Р·Р°Рґ</a></div>'))
            now = int(time.time())
            try:
                with db() as c:
                    cur = c.execute("""INSERT INTO managed_lists(title,slug,description,export_token,content,created,updated)
                                      VALUES(?,?,?,?,?,?,?)""", (data.get("title","").strip(), slug, data.get("description","").strip(), secrets.token_urlsafe(32), "", now, now))
                    list_id = cur.lastrowid
            except sqlite3.IntegrityError:
                return self.respond(409, page("РћС€РёР±РєР°", '<div class="card"><div class="notice error">РўР°РєРѕР№ РёРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚.</div><a class="button" href="/new">РќР°Р·Р°Рґ</a></div>'))
            export_path(slug).write_text("", encoding="ascii")
            return self.redirect(f"/edit/{list_id}")
        match = re.fullmatch(r"/save/(\d+)", self.path)
        if match:
            item = self.list_by_id(int(match.group(1)))
            if not item: return self.respond(404, b"not found\n", "text/plain")
            try: normalized, source_count, output_count = normalize_list(data.get("networks",""))
            except ValueError as exc: return self.respond(400, page("РћС€РёР±РєР° СЃРїРёСЃРєР°", f'<div class="card"><h1>РћС€РёР±РєР°</h1><div class="notice error">{html.escape(str(exc))}</div><a class="button" href="/edit/{item["id"]}">РќР°Р·Р°Рґ</a></div>'))
            temp = export_path(item["slug"]).with_suffix(".tmp"); temp.write_text(normalized, encoding="ascii"); os.replace(temp, export_path(item["slug"]))
            with db() as c:
                c.execute("UPDATE managed_lists SET title=?,description=?,content=?,updated=? WHERE id=?",
                          (data.get("title","").strip(), data.get("description","").strip(), normalized, int(time.time()), item["id"]))
                c.execute("INSERT INTO list_versions(list_id,created,username,source_count,output_count,content) VALUES(?,?,?,?,?,?)",
                          (item["id"], int(time.time()), session["username"], source_count, output_count, normalized))
            return self.redirect(f"/edit/{item['id']}")
        match = re.fullmatch(r"/delete/(\d+)", self.path)
        if match:
            item = self.list_by_id(int(match.group(1)))
            if item:
                with db() as c: c.execute("DELETE FROM managed_lists WHERE id=?", (item["id"],))
                export_path(item["slug"]).unlink(missing_ok=True)
            return self.redirect("/")
        return self.respond(404, b"not found\n", "text/plain")

    def log_message(self, fmt, *args): print(f"{self.client_address[0]} - {fmt % args}")


if __name__ == "__main__":
    init(); print(f"Route Portal listening on {LISTEN}:{PORT}")
    ThreadingHTTPServer((LISTEN, PORT), Handler).serve_forever()
