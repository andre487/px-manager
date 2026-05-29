import html
import json
import pathlib
import re
import secrets
import sys
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlparse

import click
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.web
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError

SESSION_TTL_SECONDS = 30 * 60
SESSION_CLEANUP_INTERVAL_MS = 60 * 1000
SESSION_COOKIE_NAME = "session"
LOGIN_FAILURE_LIMIT = 5
BAN_TTL_SECONDS = 3 * 60 * 60
BAN_CLEANUP_INTERVAL_MS = 60 * 1000
MESSAGE_HTML_CACHE: dict[str, str] = {}
LINK_RE = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
ITALIC_RE = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")

cur_dir = pathlib.Path.cwd()


def resource_path(*parts: str) -> pathlib.Path:
    base_path = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(__file__).parent))
    return base_path.joinpath(*parts)


class PasswordStore:
    def __init__(self, hashes: dict[str, str]):
        self._hashes = hashes
        self._hasher = PasswordHasher()

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "PasswordStore":
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            raise click.ClickException("passwd file must contain a JSON object")

        hashes = {}
        for username, password_hash in data.items():
            if not isinstance(username, str) or not isinstance(password_hash, str):
                raise click.ClickException(
                    "passwd file must map string usernames to string argon2 hashes"
                )
            hashes[username] = password_hash

        return cls(hashes)

    def verify(self, username: str, password: str) -> bool:
        password_hash = self._hashes.get(username)
        if password_hash is None:
            return False

        try:
            return self._hasher.verify(password_hash, password)
        except Argon2Error, VerificationError:
            return False


@dataclass(frozen=True)
class Session:
    username: str
    password: str
    expires_at: float


class SessionStore:
    def __init__(self, ttl_seconds: int):
        self._ttl_seconds = ttl_seconds
        self._sessions: dict[str, Session] = {}

    def create(self, username: str, password: str) -> str:
        self.cleanup_expired()
        session_id = secrets.token_urlsafe(32)
        self._sessions[session_id] = Session(
            username=username,
            password=password,
            expires_at=time.monotonic() + self._ttl_seconds,
        )
        return session_id

    def get(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None

        session = self._sessions.get(session_id)
        if session is None:
            return None

        if session.expires_at <= time.monotonic():
            self.delete(session_id)
            return None

        return session

    def delete(self, session_id: str | None) -> None:
        if session_id:
            self._sessions.pop(session_id, None)

    def cleanup_expired(self) -> None:
        now = time.monotonic()
        expired_session_ids = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired_session_ids:
            self.delete(session_id)


@dataclass(frozen=True)
class Ban:
    ip: str
    expires_at: float


class BanStore:
    def __init__(self, failure_limit: int, ban_ttl_seconds: int):
        self._failure_limit = failure_limit
        self._ban_ttl_seconds = ban_ttl_seconds
        self._failures: dict[str, int] = {}
        self._bans: dict[str, Ban] = {}

    def is_banned(self, ip: str) -> bool:
        ban = self._bans.get(ip)
        if ban is None:
            return False

        if ban.expires_at <= time.time():
            self.delete(ip)
            return False

        return True

    def record_failure(self, ip: str) -> None:
        if self.is_banned(ip):
            return

        failures = self._failures.get(ip, 0) + 1
        if failures >= self._failure_limit:
            self._bans[ip] = Ban(
                ip=ip,
                expires_at=time.time() + self._ban_ttl_seconds,
            )
            self._failures.pop(ip, None)
            return

        self._failures[ip] = failures

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)

    def active_bans(self) -> list[Ban]:
        self.cleanup_expired()
        return sorted(self._bans.values(), key=lambda ban: ban.expires_at)

    def delete(self, ip: str) -> None:
        self._bans.pop(ip, None)
        self._failures.pop(ip, None)

    def cleanup_expired(self) -> None:
        now = time.time()
        expired_ips = [ip for ip, ban in self._bans.items() if ban.expires_at <= now]
        for ip in expired_ips:
            self.delete(ip)


class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Referrer-Policy", "same-origin")
        self.set_header("Content-Security-Policy", build_csp_header())
        self.set_cors_headers()

    @property
    def password_store(self) -> PasswordStore:
        return self.application.settings["password_store"]

    @property
    def session_store(self) -> SessionStore:
        return self.application.settings["session_store"]

    @property
    def ban_store(self) -> BanStore:
        return self.application.settings["ban_store"]

    @property
    def hosts_data(self) -> list[dict]:
        return self.application.settings["hosts_data"]

    @property
    def data_dir(self) -> pathlib.Path:
        return self.application.settings["data_dir"]

    @property
    def admin_user(self) -> str | None:
        return self.application.settings["admin_user"]

    @property
    def is_admin(self) -> bool:
        return self.current_user is not None and self.current_user == self.admin_user

    @property
    def client_ip(self) -> str:
        forwarded_for = self.request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",", 1)[0].strip()

        real_ip = self.request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        return self.request.remote_ip

    @property
    def cors_allowed_origins(self) -> set[str]:
        return self.application.settings["cors_allowed_origins"]

    def set_cors_headers(self) -> None:
        origin = self.request.headers.get("Origin")
        if not origin or origin not in self.cors_allowed_origins:
            return

        self.set_header("Access-Control-Allow-Origin", origin)
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.set_header("Access-Control-Allow-Headers", "Content-Type, X-XSRFToken")
        self.set_header("Vary", "Origin")

    def options(self):
        origin = self.request.headers.get("Origin")
        if origin and origin not in self.cors_allowed_origins:
            self.set_status(403)
            self.finish()
            return

        self.set_status(204)
        self.finish()

    def get_current_user(self):
        session = self.get_session()
        if session is None:
            return None
        return session.username

    def get_session(self) -> Session | None:
        session_id = self.get_secure_cookie(SESSION_COOKIE_NAME)
        if session_id is None:
            return None
        return self.session_store.get(tornado.escape.to_unicode(session_id))

    def get_authenticated_credentials(self) -> tuple[str, str] | None:
        session = self.get_session()
        if session is not None:
            return session.username, session.password

        return None


class IndexHandler(BaseHandler):
    def get(self):
        if self.ban_store.is_banned(self.client_ip):
            self.set_status(403)
            self.render(
                "index.html",
                error="Too many failed login attempts. Try again later.",
                message="",
                message_html="",
                is_admin=False,
            )
            return

        message = read_message(self.data_dir)
        self.render(
            "index.html",
            error=None,
            message=message,
            message_html=compile_message_html(message),
            is_admin=self.is_admin,
        )

    def post(self):
        username = self.get_body_argument("username", "")
        password = self.get_body_argument("password", "")
        client_ip = self.client_ip

        if self.ban_store.is_banned(client_ip):
            self.set_status(403)
            self.render(
                "index.html",
                error="Too many failed login attempts. Try again later.",
                message="",
                message_html="",
                is_admin=False,
            )
            return

        if not self.password_store.verify(username, password):
            self.ban_store.record_failure(client_ip)
            self.set_status(401)
            self.render(
                "index.html",
                error="Invalid login or password",
                message="",
                message_html="",
                is_admin=False,
            )
            return

        self.ban_store.record_success(client_ip)
        session_id = self.session_store.create(username, password)
        self.set_secure_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            expires_days=SESSION_TTL_SECONDS / 86400,
            httponly=True,
            samesite="Strict",
        )
        self.redirect("/")


class LogoutHandler(BaseHandler):
    def post(self):
        session_id = self.get_secure_cookie(SESSION_COOKIE_NAME)
        if session_id is not None:
            self.session_store.delete(tornado.escape.to_unicode(session_id))
        self.clear_cookie(SESSION_COOKIE_NAME)
        self.clear_cookie("user")
        self.redirect("/")


class FaviconHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("X-Content-Type-Options", "nosniff")

    def get(self):
        self.set_header("Content-Type", "image/x-icon")
        self.set_header("Cache-Control", "public, max-age=31536000, immutable")
        self.write(resource_path("static", "favicon.ico").read_bytes())


class AdminHandler(BaseHandler):
    def prepare(self):
        if self.current_user is None:
            self.redirect("/")
            raise tornado.web.Finish()

        if not self.is_admin:
            self.set_status(403)
            self.finish("Forbidden")

    def get(self):
        self.render(
            "admin.html",
            message=read_message(self.data_dir),
            saved=False,
            active_bans=self.ban_store.active_bans(),
            format_timestamp=format_timestamp,
        )

    def post(self):
        write_message(self.data_dir, self.get_body_argument("message", ""))
        self.render(
            "admin.html",
            message=read_message(self.data_dir),
            saved=True,
            active_bans=self.ban_store.active_bans(),
            format_timestamp=format_timestamp,
        )


class ApiHandler(BaseHandler):
    def prepare(self):
        if self.request.method == "OPTIONS":
            return

        self.authenticated_credentials = self.get_authenticated_credentials()
        if self.authenticated_credentials is None:
            self.set_status(401)
            self.finish({"error": "authentication required"})

    def get(self):
        self.write(
            {
                "ok": True,
                "user": self.authenticated_credentials[0],  # type: ignore
            }
        )


class ProxyListGenerateHandler(BaseHandler):
    def prepare(self):
        if self.request.method == "OPTIONS":
            return

        self.authenticated_credentials = self.get_authenticated_credentials()
        if self.authenticated_credentials is None:
            self.set_status(401)
            self.finish({"error": "authentication required"})

    def get(self):
        username, password = self.authenticated_credentials  # type: ignore
        proxy_type = self.get_query_argument("type", "https").lower()
        default_port = self.get_query_argument("port", "443")

        if proxy_type not in {"http", "https", "ssl", "socks", "socks4", "socks5"}:
            self.set_status(400)
            self.finish({"error": "unsupported proxy type"})
            return

        lines = [
            build_proxy_list_line(
                item,
                username=username,
                password=password,
                proxy_type=proxy_type,
                default_port=default_port,
            )
            for item in self.hosts_data
        ]

        self.set_header("Content-Type", "text/plain; charset=utf-8")
        self.set_header(
            "Content-Disposition",
            f'attachment; filename="{build_proxy_list_filename(username)}"',
        )
        self.write("\n".join(lines) + "\n")


class FoxyProxyGenerateHandler(BaseHandler):
    def prepare(self):
        if self.request.method == "OPTIONS":
            return

        self.authenticated_credentials = self.get_authenticated_credentials()
        if self.authenticated_credentials is None:
            self.set_status(401)
            self.finish({"error": "authentication required"})

    def get(self):
        username, password = self.authenticated_credentials  # type: ignore
        proxy_type = self.get_query_argument("type", "https").lower()
        default_port = self.get_query_argument("port", "443")

        if proxy_type not in {"http", "https", "ssl", "socks", "socks4", "socks5"}:
            self.set_status(400)
            self.finish({"error": "unsupported proxy type"})
            return

        config = build_foxy_proxy_config(
            self.hosts_data,
            username=username,
            password=password,
            proxy_type=proxy_type,
            default_port=default_port,
        )

        self.set_header("Content-Type", "application/json; charset=utf-8")
        self.set_header(
            "Content-Disposition",
            f'attachment; filename="{build_foxy_proxy_filename(username)}"',
        )
        self.write(json.dumps(config, indent=2))
        self.write("\n")


def build_proxy_list_line(
    host_data: dict,
    *,
    username: str,
    password: str,
    proxy_type: str,
    default_port: str,
) -> str:
    host = host_data["host"]
    port = str(host_data.get("port", default_port))
    title = host_data.get("title") or host_data.get("code") or host
    code = host_data.get("code")

    params = {
        "title": title,
        "patternIncludesAll": "false",
        "patternExcludesIntranet": "false",
    }
    if code:
        params["cc"] = code

    return (
        f"{proxy_type}://{quote(username, safe='')}:"
        f"{quote(password, safe='')}@{host}:{port}?{urlencode(params)}"
    )


def build_proxy_list_filename(username: str) -> str:
    safe_username = re.sub(r"[^A-Za-z0-9_.-]+", "_", username).strip("._-")
    if not safe_username:
        safe_username = "user"
    return f"{safe_username}-proxy-list.txt"


def build_foxy_proxy_config(
    hosts_data: list[dict],
    *,
    username: str,
    password: str,
    proxy_type: str,
    default_port: str,
) -> dict:
    proxies = [
        build_foxy_proxy_entry(
            item,
            username=username,
            password=password,
            proxy_type=proxy_type,
            default_port=default_port,
            color=pick_proxy_color(index),
        )
        for index, item in enumerate(hosts_data)
    ]

    return {
        "mode": build_foxy_proxy_mode(proxies),
        "sync": False,
        "autoBackup": False,
        "passthrough": "",
        "theme": "",
        "container": {},
        "commands": {
            "setProxy": "",
            "setTabProxy": "",
            "includeHost": "",
            "excludeHost": "",
        },
        "data": proxies,
    }


def build_foxy_proxy_entry(
    host_data: dict,
    *,
    username: str,
    password: str,
    proxy_type: str,
    default_port: str,
    color: str,
) -> dict:
    host = host_data["host"]
    port = str(host_data.get("port", default_port))
    title = host_data.get("title") or host_data.get("code") or host
    code = str(host_data.get("code", "")).upper()

    return {
        "active": True,
        "title": f"{title} Proxy",
        "type": proxy_type,
        "hostname": host,
        "port": port,
        "username": username,
        "password": password,
        "cc": code,
        "city": "",
        "color": color,
        "pac": "",
        "pacString": "",
        "proxyDNS": True,
        "include": [],
        "exclude": [],
        "tabProxy": [],
    }


def build_foxy_proxy_mode(proxies: list[dict]) -> str:
    if not proxies:
        return ""
    first_proxy = proxies[0]
    return f"{first_proxy['hostname']}:{first_proxy['port']}"


def pick_proxy_color(index: int) -> str:
    colors = [
        "#5f3efb",
        "#b9c6f6",
        "#eef209",
        "#3100f1",
        "#8b0000",
        "#198754",
        "#fd7e14",
        "#0dcaf0",
    ]
    return colors[index % len(colors)]


def build_foxy_proxy_filename(username: str) -> str:
    safe_username = re.sub(r"[^A-Za-z0-9_.-]+", "_", username).strip("._-")
    if not safe_username:
        safe_username = "user"
    return f"{safe_username}-foxy-proxy.json"


def build_csp_header() -> str:
    return "; ".join(
        [
            "default-src 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "img-src 'self'",
            "object-src 'none'",
            "script-src 'none'",
            "style-src 'self'",
        ]
    )


def read_optional_text(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text().strip()


def read_message(data_dir: pathlib.Path) -> str:
    return read_optional_text(data_dir / "message.md")


def compile_message_html(message: str) -> str:
    cached_html = MESSAGE_HTML_CACHE.get(message)
    if cached_html is not None:
        return cached_html

    compiled = render_message_markdown(message)
    MESSAGE_HTML_CACHE.clear()
    MESSAGE_HTML_CACHE[message] = compiled
    return compiled


def render_message_markdown(message: str) -> str:
    parts = []
    last_pos = 0

    for match in LINK_RE.finditer(message):
        parts.append(render_inline_markdown(message[last_pos : match.start()]))
        parts.append(render_link(match.group(1), match.group(2), match.group(0)))
        last_pos = match.end()

    parts.append(render_inline_markdown(message[last_pos:]))
    return "".join(parts)


def render_link(text: str, url: str, fallback: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https", "mailto"}:
        return render_inline_markdown(fallback)

    return (
        f'<a href="{html.escape(url, quote=True)}" '
        f'target="_blank" rel="noopener noreferrer">'
        f"{render_inline_markdown(text)}</a>"
    )


def render_inline_markdown(text: str) -> str:
    escaped_text = html.escape(text)
    escaped_text = BOLD_RE.sub(r"<strong>\1</strong>", escaped_text)
    return ITALIC_RE.sub(r"<em>\1</em>", escaped_text)


def write_message(data_dir: pathlib.Path, message: str) -> None:
    (data_dir / "message.md").write_text(message.strip())


def format_timestamp(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def make_app(data_dir: pathlib.Path, cookie_secret: str) -> tornado.web.Application:
    hosts_data = json.loads((data_dir / "hosts.json").read_text())
    admin_user = read_optional_text(data_dir / "admin.txt") or None

    session_store = SessionStore(SESSION_TTL_SECONDS)
    ban_store = BanStore(LOGIN_FAILURE_LIMIT, BAN_TTL_SECONDS)
    return tornado.web.Application(
        [
            (r"/", IndexHandler),
            (r"/admin", AdminHandler),
            (r"/logout", LogoutHandler),
            (r"/favicon.ico", FaviconHandler),
            (r"/api", ApiHandler),
            (r"/api/generate/proxy-list", ProxyListGenerateHandler),
            (r"/api/generate/foxy-proxy", FoxyProxyGenerateHandler),
        ],
        cookie_secret=cookie_secret,
        xsrf_cookies=True,
        xsrf_cookie_kwargs={
            "httponly": True,
            "samesite": "Strict",
        },
        static_path=str(resource_path("static")),
        template_path=str(resource_path("templates")),
        data_dir=data_dir,
        admin_user=admin_user,
        password_store=PasswordStore.from_file(data_dir / "passwd.json"),
        hosts_data=hosts_data,
        session_store=session_store,
        ban_store=ban_store,
        cors_allowed_origins=set(),
    )


@click.command()
@click.option(
    "--data-dir",
    type=click.Path(
        exists=True,
        dir_okay=True,
        file_okay=False,
        path_type=pathlib.Path,
    ),
    default=cur_dir / "data",
)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8888, show_default=True, type=int)
@click.option(
    "--cors-origin",
    multiple=True,
    help="Allowed CORS origin. Can be passed multiple times. Cookies are allowed only for these exact origins.",
)
@click.option(
    "--cookie-secret",
    envvar="PX_MANAGER_COOKIE_SECRET",
    help="Secret used to sign session cookies. Defaults to a random startup secret.",
)
def main(
    data_dir: pathlib.Path,
    host: str,
    port: int,
    cors_origin: tuple[str, ...],
    cookie_secret: str | None,
):
    if not cookie_secret:
        cookie_secret = secrets.token_urlsafe(32)

    app = make_app(data_dir, cookie_secret)
    app.settings["cors_allowed_origins"] = set(cors_origin)
    server = tornado.httpserver.HTTPServer(app)
    server.listen(port, address=host)
    session_cleanup = tornado.ioloop.PeriodicCallback(
        app.settings["session_store"].cleanup_expired,
        SESSION_CLEANUP_INTERVAL_MS,
    )
    session_cleanup.start()
    ban_cleanup = tornado.ioloop.PeriodicCallback(
        app.settings["ban_store"].cleanup_expired,
        BAN_CLEANUP_INTERVAL_MS,
    )
    ban_cleanup.start()
    click.echo(f"Listening on http://{host}:{port}")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
