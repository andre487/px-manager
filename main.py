import html
import hashlib
import json
import logging
import pathlib
import re
import secrets
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from urllib.parse import quote, urlencode, urlparse

import click
import tornado.escape
import tornado.log
import tornado.httpserver
import tornado.ioloop
import tornado.web
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError

SESSION_TTL_SECONDS = 30 * 60
SESSION_CLEANUP_INTERVAL_MS = 60 * 1000
SESSION_COOKIE_NAME = "session"
TLS_FINGERPRINT_TTL_SECONDS = 6 * 60 * 60
LOG_MAX_BYTES = 100 * 1024 * 1024
LOG_BACKUP_COUNT = 1
LOGIN_FAILURE_LIMIT = 5
AUTH_FAILURE_LIMIT = 20
FAILURE_WINDOW_SECONDS = 60 * 60
BAN_TTL_SECONDS = 3 * 60 * 60
BAN_CLEANUP_INTERVAL_MS = 60 * 1000
MESSAGE_HTML_CACHE: dict[str, str] = {}
LINK_RE = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
ITALIC_RE = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
AUTH_LOG = logging.getLogger("px_manager.auth")
BAN_LOG = logging.getLogger("px_manager.ban")

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
    def __init__(self, ban_ttl_seconds: int, failure_window_seconds: int):
        self._ban_ttl_seconds = ban_ttl_seconds
        self._failure_window_seconds = failure_window_seconds
        self._login_failures: dict[str, list[float]] = {}
        self._auth_failures: dict[str, list[float]] = {}
        self._bans: dict[str, Ban] = {}

    def is_banned(self, ip: str) -> bool:
        ban = self._bans.get(ip)
        if ban is None:
            return False

        if ban.expires_at <= time.time():
            self.delete(ip)
            return False

        return True

    def record_login_failure(self, ip: str) -> None:
        self._record_failure(
            self._login_failures,
            ip,
            LOGIN_FAILURE_LIMIT,
            failure_type="login",
        )

    def record_auth_failure(self, ip: str) -> None:
        self._record_failure(
            self._auth_failures,
            ip,
            AUTH_FAILURE_LIMIT,
            failure_type="auth",
        )

    def _record_failure(
        self,
        failures_by_ip: dict[str, list[float]],
        ip: str,
        failure_limit: int,
        *,
        failure_type: str,
    ) -> None:
        if self.is_banned(ip):
            return

        now = time.time()
        failures = [
            failure_time
            for failure_time in failures_by_ip.get(ip, [])
            if failure_time > now - self._failure_window_seconds
        ]
        failures.append(now)

        if len(failures) >= failure_limit:
            expires_at = now + self._ban_ttl_seconds
            self._bans[ip] = Ban(
                ip=ip,
                expires_at=expires_at,
            )
            BAN_LOG.warning(
                "ban_created ip=%s failure_type=%s failures=%d limit=%d expires_at=%s",
                ip,
                failure_type,
                len(failures),
                failure_limit,
                format_timestamp(expires_at),
            )
            self._login_failures.pop(ip, None)
            self._auth_failures.pop(ip, None)
            return

        failures_by_ip[ip] = failures

    def record_success(self, ip: str) -> None:
        self._login_failures.pop(ip, None)

    def active_bans(self) -> list[Ban]:
        self.cleanup_expired()
        return sorted(self._bans.values(), key=lambda ban: ban.expires_at)

    def delete(self, ip: str) -> None:
        ban = self._bans.pop(ip, None)
        if ban is not None:
            BAN_LOG.info("ban_deleted ip=%s", ip)
        self._login_failures.pop(ip, None)
        self._auth_failures.pop(ip, None)

    def cleanup_expired(self) -> None:
        now = time.time()
        expired_ips = [ip for ip, ban in self._bans.items() if ban.expires_at <= now]
        for ip in expired_ips:
            self.delete(ip)

        self._cleanup_failures(self._login_failures, now)
        self._cleanup_failures(self._auth_failures, now)

    def _cleanup_failures(
        self,
        failures_by_ip: dict[str, list[float]],
        now: float,
    ) -> None:
        for ip, failures in list(failures_by_ip.items()):
            recent_failures = [
                failure_time
                for failure_time in failures
                if failure_time > now - self._failure_window_seconds
            ]
            if recent_failures:
                failures_by_ip[ip] = recent_failures
            else:
                failures_by_ip.pop(ip, None)


class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Frame-Options", "DENY")
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
        real_ip = self.request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        return self.request.remote_ip # type: ignore

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

    def require_authenticated_credentials(self) -> tuple[str, str] | None:
        credentials = self.get_authenticated_credentials()
        if credentials is not None:
            return credentials

        self.ban_store.record_auth_failure(self.client_ip)
        self.set_status(403)
        self.finish({"error": "forbidden"})
        return None


class IndexHandler(BaseHandler):
    def get(self):
        if self.ban_store.is_banned(self.client_ip):
            self.set_status(403)
            self.render(
                "index.html",
                error="Слишком много неудачных попыток входа. Попробуйте позже.",
                message="",
                message_html="",
                tg_proxies=[],
                is_admin=False,
            )
            return

        message = read_message(self.data_dir)
        self.render(
            "index.html",
            error=None,
            message=message,
            message_html=compile_message_html(message),
            tg_proxies=read_tg_proxies(self.data_dir),
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
                error="Слишком много неудачных попыток входа. Попробуйте позже.",
                message="",
                message_html="",
                tg_proxies=[],
                is_admin=False,
            )
            return

        if not self.password_store.verify(username, password):
            self.ban_store.record_login_failure(client_ip)
            self.set_status(401)
            self.render(
                "index.html",
                error="Неверный логин или пароль",
                message="",
                message_html="",
                tg_proxies=[],
                is_admin=False,
            )
            return

        self.ban_store.record_success(client_ip)
        AUTH_LOG.info("login_success ip=%s user=%s", client_ip, username)
        self.access_log_username = username
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
        self.set_header("Cache-Control", "public, max-age=3600, must-revalidate")
        self.write(resource_path("static", "favicon.ico").read_bytes())


class RobotsHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("X-Content-Type-Options", "nosniff")

    def get(self):
        self.set_header("Content-Type", "text/plain; charset=utf-8")
        self.write(resource_path("static", "robots.txt").read_text())


class AdminHandler(BaseHandler):
    def prepare(self):
        if self.current_user is None:
            self.redirect("/")
            raise tornado.web.Finish()

        if not self.is_admin:
            self.set_status(403)
            self.finish("Доступ запрещён")

    def get(self):
        self.render(
            "admin.html",
            message=read_message(self.data_dir),
            tg_proxies=read_tg_proxies_text(self.data_dir),
            saved=False,
            active_bans=self.ban_store.active_bans(),
            format_timestamp=format_timestamp,
        )

    def post(self):
        write_message(self.data_dir, self.get_body_argument("message", ""))
        write_tg_proxies(self.data_dir, self.get_body_argument("tg_proxies", ""))
        self.render(
            "admin.html",
            message=read_message(self.data_dir),
            tg_proxies=read_tg_proxies_text(self.data_dir),
            saved=True,
            active_bans=self.ban_store.active_bans(),
            format_timestamp=format_timestamp,
        )


class DocHandler(BaseHandler):
    def prepare(self):
        if self.current_user is None:
            self.redirect("/")
            raise tornado.web.Finish()

    def get(self):
        self.render("doc.html")


class ApiHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    def get(self):
        self.write(
            {
                "ok": True,
                "user": self.authenticated_credentials[0],  # type: ignore
            }
        )


class ProxyListGenerateHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

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


class SuperProxyGenerateHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    def get(self):
        username, password = self.authenticated_credentials  # type: ignore
        default_port = self.get_query_argument("port", "443")
        try:
            config = build_super_proxy_config(
                self.hosts_data,
                username=username,
                password=password,
                default_port=default_port,
            )
        except (OSError, ssl.SSLError, RuntimeError) as error:
            self.set_status(502)
            self.finish({"error": f"failed to fetch TLS fingerprint: {error}"})
            return

        self.set_header("Content-Type", "text/plain; charset=utf-8")
        self.set_header(
            "Content-Disposition",
            f'attachment; filename="{build_super_proxy_filename(username)}"',
        )
        self.write(config)


class FoxyProxyGenerateHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

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


class ShadowrocketGenerateHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    def get(self):
        username, password = self.authenticated_credentials  # type: ignore
        proxy_type = self.get_query_argument("type", "https").lower()
        default_port = self.get_query_argument("port", "443")

        if proxy_type not in {"http", "https", "socks5"}:
            self.set_status(400)
            self.finish({"error": "unsupported proxy type"})
            return

        config = build_shadowrocket_config(
            self.hosts_data,
            username=username,
            password=password,
            proxy_type=proxy_type,
            default_port=default_port,
        )

        self.set_header("Content-Type", "text/plain; charset=utf-8")
        self.set_header(
            "Content-Disposition",
            f'attachment; filename="{build_shadowrocket_filename(username)}"',
        )
        self.write(config)


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


def build_super_proxy_config(
    hosts_data: list[dict],
    *,
    username: str,
    password: str,
    default_port: str,
) -> str:
    lines = ["# superproxy:proxylist:v1"]
    lines.extend(
        build_super_proxy_line(
            item,
            username=username,
            password=password,
            default_port=default_port,
            is_default=index == 0,
        )
        for index, item in enumerate(hosts_data)
    )
    return "\n".join(lines) + "\n"


def build_super_proxy_line(
    host_data: dict,
    *,
    username: str,
    password: str,
    default_port: str,
    is_default: bool,
) -> str:
    host = host_data["host"]
    port = str(host_data.get("port", default_port))
    title = str(host_data.get("code") or host_data.get("title") or host)
    fingerprint = get_tls_fingerprint(host, int(port))
    fingerprint_query = f"?fingerprint={quote(fingerprint, safe='')}"
    default_marker = " *" if is_default else ""
    return (
        f"https://{quote(username, safe='')}:"
        f"{quote(password, safe='')}@{host}:{port}{fingerprint_query} "
        f'"{escape_super_proxy_title(title)}"{default_marker}'
    )


def get_tls_fingerprint(host: str, port: int) -> str:
    ttl_bucket = int(time.time() // TLS_FINGERPRINT_TTL_SECONDS)
    return get_cached_tls_fingerprint(host, port, ttl_bucket)


@lru_cache(maxsize=256)
def get_cached_tls_fingerprint(host: str, port: int, ttl_bucket: int) -> str:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            certificate_der = tls_socket.getpeercert(binary_form=True)
    if certificate_der is None:
        raise RuntimeError(f"TLS certificate is unavailable for {host}:{port}")
    return hashlib.sha1(certificate_der).hexdigest()


def escape_super_proxy_title(title: str) -> str:
    return title.replace("\\", "\\\\").replace('"', '\\"')


def build_super_proxy_filename(username: str) -> str:
    safe_username = re.sub(r"[^A-Za-z0-9_.-]+", "_", username).strip("._-")
    if not safe_username:
        safe_username = "user"
    return f"{safe_username}-super-proxy.txt"


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
        "title": title,
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


def build_shadowrocket_config(
    hosts_data: list[dict],
    *,
    username: str,
    password: str,
    proxy_type: str,
    default_port: str,
) -> str:
    proxy_names = [
        build_shadowrocket_proxy_name(item, index)
        for index, item in enumerate(hosts_data, start=1)
    ]
    lines = [
        "[General]",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local",
        "",
        "[Proxy]",
    ]
    lines.extend(
        build_shadowrocket_proxy_line(
            item,
            name=name,
            username=username,
            password=password,
            proxy_type=proxy_type,
            default_port=default_port,
        )
        for item, name in zip(hosts_data, proxy_names)
    )
    lines.extend(
        [
            "",
            "[Proxy Group]",
            f"PROXY = select, {', '.join(proxy_names)}, DIRECT",
            "",
            "[Rule]",
            "FINAL,PROXY",
            "",
        ]
    )
    return "\n".join(lines)


def build_shadowrocket_proxy_line(
    host_data: dict,
    *,
    name: str,
    username: str,
    password: str,
    proxy_type: str,
    default_port: str,
) -> str:
    host = host_data["host"]
    port = str(host_data.get("port", default_port))
    return (
        f"{name} = {proxy_type}, {host}, {port}, "
        f"username={escape_shadowrocket_value(username)}, "
        f"password={escape_shadowrocket_value(password)}"
    )


def build_shadowrocket_proxy_name(host_data: dict, index: int) -> str:
    title = str(host_data.get("title") or host_data.get("code") or host_data["host"])
    safe_title = re.sub(r"[^A-Za-z0-9_.-]+", "_", title).strip("._-")
    if not safe_title:
        safe_title = f"Proxy {index}"
    return f"{safe_title}_{index}"


def escape_shadowrocket_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace(",", "\\,")


def build_shadowrocket_filename(username: str) -> str:
    safe_username = re.sub(r"[^A-Za-z0-9_.-]+", "_", username).strip("._-")
    if not safe_username:
        safe_username = "user"
    return f"{safe_username}-shadowrocket.conf"


def build_csp_header() -> str:
    return "; ".join(
        [
            "default-src 'self'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "img-src 'self'",
            "navigate-to 'self' tg:",
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


def read_tg_proxies_text(data_dir: pathlib.Path) -> str:
    return read_optional_text(data_dir / "tg-proxies.txt")


def read_tg_proxies(data_dir: pathlib.Path) -> list[str]:
    return [
        line.strip()
        for line in read_tg_proxies_text(data_dir).splitlines()
        if line.strip().startswith("tg://")
    ]


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


def write_tg_proxies(data_dir: pathlib.Path, tg_proxies: str) -> None:
    (data_dir / "tg-proxies.txt").write_text(tg_proxies.strip())


def format_timestamp(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def configure_logging(log_dir: pathlib.Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    configure_tagged_logger(
        logging.getLogger("tornado.access"),
        tag="access",
        log_file=log_dir / "access.log",
    )
    configure_tagged_logger(
        AUTH_LOG,
        tag="auth",
        log_file=log_dir / "auth.log",
    )
    configure_tagged_logger(
        BAN_LOG,
        tag="ban",
        log_file=log_dir / "ban.log",
    )


def configure_tagged_logger(
    logger: logging.Logger,
    *,
    tag: str,
    log_file: pathlib.Path,
) -> None:
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    formatter = logging.Formatter(
        f"%(asctime)s %(levelname)s [{tag}] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    stderr_handler = logging.StreamHandler()
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


class PxManagerApplication(tornado.web.Application):
    def log_request(self, handler: tornado.web.RequestHandler) -> None:
        status = handler.get_status()
        if status < 400:
            log_method = tornado.log.access_log.info
        elif status < 500:
            log_method = tornado.log.access_log.warning
        else:
            log_method = tornado.log.access_log.error

        request_time_ms = 1000.0 * handler.request.request_time()
        log_method(
            "%d %s %s ip=%s user=%s %.2fms",
            status,
            handler.request.method,
            handler.request.uri,
            get_access_log_ip(handler),
            get_access_log_username(handler),
            request_time_ms,
        )


def get_access_log_ip(handler: tornado.web.RequestHandler) -> str:
    if isinstance(handler, BaseHandler):
        return handler.client_ip

    real_ip = handler.request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return handler.request.remote_ip  # type: ignore


def get_access_log_username(handler: tornado.web.RequestHandler) -> str:
    username = getattr(handler, "access_log_username", None)
    if username:
        return str(username)

    if isinstance(handler, BaseHandler) and handler.current_user:
        return str(handler.current_user)

    return "-"


def make_app(data_dir: pathlib.Path, cookie_secret: str) -> tornado.web.Application:
    hosts_data = json.loads((data_dir / "hosts.json").read_text())
    admin_user = read_optional_text(data_dir / "admin.txt") or None

    session_store = SessionStore(SESSION_TTL_SECONDS)
    ban_store = BanStore(BAN_TTL_SECONDS, FAILURE_WINDOW_SECONDS)
    return PxManagerApplication(
        [
            (r"/", IndexHandler),
            (r"/admin", AdminHandler),
            (r"/doc", DocHandler),
            (r"/logout", LogoutHandler),
            (r"/favicon.ico", FaviconHandler),
            (r"/robots.txt", RobotsHandler),
            (r"/api", ApiHandler),
            (r"/api/generate/proxy-list", ProxyListGenerateHandler),
            (r"/api/generate/super-proxy", SuperProxyGenerateHandler),
            (r"/api/generate/foxy-proxy", FoxyProxyGenerateHandler),
            (r"/api/generate/shadowrocket", ShadowrocketGenerateHandler),
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
@click.option(
    "--log-dir",
    type=click.Path(
        dir_okay=True,
        file_okay=False,
        path_type=pathlib.Path,
    ),
    default=cur_dir / "logs",
    show_default=True,
    help="Directory for access/auth/ban log files.",
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
    log_dir: pathlib.Path,
    host: str,
    port: int,
    cors_origin: tuple[str, ...],
    cookie_secret: str | None,
):
    if not cookie_secret:
        cookie_secret = secrets.token_urlsafe(32)

    configure_logging(log_dir)
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
