import html
import hashlib
import asyncio
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
import dns.asyncresolver
import dns.exception
import dns.resolver
import dns.rdatatype
import icmplib
import tornado.escape
import tornado.log
import tornado.httpserver
import tornado.ioloop
import tornado.web
from user_agents import parse as parse_user_agent
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError

SESSION_TTL_SECONDS = 30 * 60
SESSION_CLEANUP_INTERVAL_MS = 60 * 1000
SESSION_COOKIE_NAME = "session"
TLS_FINGERPRINT_TTL_SECONDS = 6 * 60 * 60
HEALTH_CACHE_TTL_SECONDS = 25
LOG_MAX_BYTES = 100 * 1024 * 1024
LOG_BACKUP_COUNT = 1
LOGIN_FAILURE_LIMIT = 5
AUTH_FAILURE_LIMIT = 20
FAILURE_WINDOW_SECONDS = 60 * 60
BAN_TTL_SECONDS = 3 * 60 * 60
BAN_CLEANUP_INTERVAL_MS = 60 * 1000
MESSAGE_HTML_CACHE: dict[str, str] = {}
HEALTH_RESULT_CACHE: dict[tuple[str, str], tuple[float, dict[str, object]]] = {}
LINK_RE = re.compile(r"\[([^\]\n]+)\]\(([^)\s]+)\)")
BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
ITALIC_RE = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
AUTH_LOG = logging.getLogger("px_manager.auth")
BAN_LOG = logging.getLogger("px_manager.ban")
ERROR_LOG = logging.getLogger("px_manager.error")
ERROR_PAGE_COPY = {
    400: ("Некорректный запрос", "Проверьте адрес или параметры запроса."),
    403: ("Доступ закрыт", "У этой сессии нет доступа к запрошенной странице."),
    404: ("Страница не найдена", "Такой страницы в PX Manager нет."),
    405: ("Метод не поддерживается", "Эта страница не принимает выбранный метод запроса."),
}
CLIENT_HINT_HEADERS = (
    "Sec-CH-UA",
    "Sec-CH-UA-Full-Version-List",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Model",
    "Sec-CH-UA-Platform",
    "Sec-CH-UA-Platform-Version",
)
CLIENT_HINT_HEADER_VALUE = ", ".join(CLIENT_HINT_HEADERS)

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
    os: str = "-"
    browser: str = "-"
    device: str = "-"


@dataclass(frozen=True)
class AccessLogClient:
    os: str
    browser: str
    device: str


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

    def record_login_failure(
        self,
        ip: str,
        client: AccessLogClient | None = None,
    ) -> None:
        self._record_failure(
            self._login_failures,
            ip,
            LOGIN_FAILURE_LIMIT,
            failure_type="login",
            client=client,
        )

    def record_auth_failure(
        self,
        ip: str,
        client: AccessLogClient | None = None,
    ) -> None:
        self._record_failure(
            self._auth_failures,
            ip,
            AUTH_FAILURE_LIMIT,
            failure_type="auth",
            client=client,
        )

    def _record_failure(
        self,
        failures_by_ip: dict[str, list[float]],
        ip: str,
        failure_limit: int,
        *,
        failure_type: str,
        client: AccessLogClient | None = None,
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
                os=client.os if client else "-",
                browser=client.browser if client else "-",
                device=client.device if client else "-",
            )
            BAN_LOG.warning(
                "ban_created ip=%s failure_type=%s failures=%d limit=%d expires_at=%s os=%s browser=%s device=%s",
                ip,
                failure_type,
                len(failures),
                failure_limit,
                format_timestamp(expires_at),
                format_log_value(client.os if client else "-"),
                format_log_value(client.browser if client else "-"),
                format_log_value(client.device if client else "-"),
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
            BAN_LOG.info(
                "ban_deleted ip=%s os=%s browser=%s device=%s",
                ip,
                format_log_value(ban.os),
                format_log_value(ban.browser),
                format_log_value(ban.device),
            )
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


class PersistentBanStore(BanStore):
    def __init__(
        self,
        ban_ttl_seconds: int,
        failure_window_seconds: int,
        state_path: pathlib.Path,
    ):
        super().__init__(ban_ttl_seconds, failure_window_seconds)
        self._state_path = state_path
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._state_path.read_text())
        except FileNotFoundError:
            return
        except json.JSONDecodeError as error:
            BAN_LOG.error("ban_state_load_failed path=%s error=%s", self._state_path, error)
            return

        now = time.time()
        if not isinstance(data, list):
            BAN_LOG.error("ban_state_load_failed path=%s error=invalid_format", self._state_path)
            return

        for item in data:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            expires_at = item.get("expires_at")
            if not isinstance(ip, str) or not isinstance(expires_at, (int, float)):
                continue
            if expires_at > now:
                self._bans[ip] = Ban(
                    ip=ip,
                    expires_at=float(expires_at),
                    os=item.get("os") if isinstance(item.get("os"), str) else "-", # type: ignore
                    browser=item.get("browser")
                    if isinstance(item.get("browser"), str)
                    else "-", # type: ignore
                    device=item.get("device")
                    if isinstance(item.get("device"), str)
                    else "-", # type: ignore
                )

        self.cleanup_expired()

    def _save(self) -> None:
        data = [
            {
                "ip": ban.ip,
                "expires_at": ban.expires_at,
                "os": ban.os,
                "browser": ban.browser,
                "device": ban.device,
            }
            for ban in sorted(self._bans.values(), key=lambda item: item.ip)
        ]
        tmp_path = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        tmp_path.replace(self._state_path)

    def _record_failure(
        self,
        failures_by_ip: dict[str, list[float]],
        ip: str,
        failure_limit: int,
        *,
        failure_type: str,
        client: AccessLogClient | None = None,
    ) -> None:
        before = set(self._bans)
        super()._record_failure(
            failures_by_ip,
            ip,
            failure_limit,
            failure_type=failure_type,
            client=client,
        )
        if set(self._bans) != before:
            self._save()

    def delete(self, ip: str) -> None:
        had_ban = ip in self._bans
        super().delete(ip)
        if had_ban:
            self._save()

    def cleanup_expired(self) -> None:
        before = set(self._bans)
        super().cleanup_expired()
        if set(self._bans) != before:
            self._save()


class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Frame-Options", "DENY")
        self.set_header("Referrer-Policy", "same-origin")
        self.set_header("Content-Security-Policy", build_csp_header())
        set_client_hint_headers(self)
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
        append_vary_header(self, CLIENT_HINT_HEADERS)

    def options(self):
        origin = self.request.headers.get("Origin")
        if origin and origin not in self.cors_allowed_origins:
            self.set_status(403)
            self.finish()
            return

        self.set_status(204)
        self.finish()

    def write_error(self, status_code: int, **kwargs) -> None:
        if status_code >= 500 and not getattr(self, "_error_logged", False):
            log_request_error(
                self,
                status_code,
                kwargs.get("exc_info"),
            )
        self.render_error_page(status_code)

    def log_exception(self, typ, value, tb) -> None:
        if isinstance(value, tornado.web.HTTPError) and value.status_code < 500:
            return

        self._error_logged = True
        log_request_error(
            self,
            value.status_code if isinstance(value, tornado.web.HTTPError) else 500,
            (typ, value, tb),
        )

    def render_error_page(self, status_code: int) -> None:
        title, message = get_error_page_copy(status_code)
        self.set_status(status_code)
        self.render(
            "error.html",
            status_code=status_code,
            title=title,
            message=message,
        )

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

        self.ban_store.record_auth_failure(
            self.client_ip,
            get_access_log_client(self),
        )
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
            client = get_access_log_client(self)
            self.ban_store.record_login_failure(
                client_ip,
                client,
            )
            AUTH_LOG.warning(
                "login_failure ip=%s user=%s os=%s browser=%s device=%s",
                client_ip,
                username or "-",
                format_log_value(client.os),
                format_log_value(client.browser),
                format_log_value(client.device),
            )
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
        client = get_access_log_client(self)
        AUTH_LOG.info(
            "login_success ip=%s user=%s os=%s browser=%s device=%s",
            client_ip,
            username,
            format_log_value(client.os),
            format_log_value(client.browser),
            format_log_value(client.device),
        )
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


class ErrorPageHandler(BaseHandler):
    def prepare(self):
        self.render_error_page(404)
        raise tornado.web.Finish()


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


class HealthPageHandler(BaseHandler):
    def prepare(self):
        if self.current_user is None:
            self.redirect("/")
            raise tornado.web.Finish()

    def get(self):
        self.render("health.html", hosts_data=self.hosts_data)


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


class HealthConnectHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    async def get(self):
        host_data = self.get_allowed_health_host()
        if host_data is None:
            return

        host = host_data["host"]
        cached_result = get_cached_health_result("connect", host)
        if cached_result is not None:
            self.write(cached_result)
            return

        result: dict[str, object] = {
            "ok": False,
            "host": host,
            "port": None,
            "status": "error",
            "error": None,
        }

        writer: asyncio.StreamWriter | None = None
        try:
            port = get_host_port(host_data)
            result["port"] = port
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2,
            )
        except Exception as error:
            result["error"] = str(error) or error.__class__.__name__
        else:
            result["ok"] = True
            result["status"] = "connected"
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        set_cached_health_result("connect", host, result)
        self.write(result)

    def get_allowed_health_host(self) -> dict | None:
        host = self.get_query_argument("host", "")
        host_data = find_host_data(self.hosts_data, host)
        if host_data is None:
            self.set_status(400)
            self.finish({"error": "host is not allowed"})
            return None
        return host_data


class HealthDnsHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    async def get(self):
        host_data = self.get_allowed_health_host()
        if host_data is None:
            return

        host = host_data["host"]
        cached_result = get_cached_health_result("dns", host)
        if cached_result is not None:
            self.write(cached_result)
            return

        result: dict[str, object] = {
            "ok": False,
            "host": host,
            "status": "error",
            "addresses": [],
            "error": None,
        }

        try:
            dns_result = await resolve_host_addresses(host)
            result.update(dns_result)
        except Exception as error:
            result["error"] = str(error) or error.__class__.__name__

        set_cached_health_result("dns", host, result)
        self.write(result)

    def get_allowed_health_host(self) -> dict | None:
        host = self.get_query_argument("host", "")
        host_data = find_host_data(self.hosts_data, host)
        if host_data is None:
            self.set_status(400)
            self.finish({"error": "host is not allowed"})
            return None
        return host_data


class HealthHeadHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    async def get(self):
        host_data = self.get_allowed_health_host()
        if host_data is None:
            return

        host = host_data["host"]
        cached_result = get_cached_health_result("proxy_request", host)
        if cached_result is not None:
            self.write(cached_result)
            return

        result: dict[str, object] = {
            "ok": False,
            "host": host,
            "port": None,
            "status": "error",
            "status_code": None,
            "status_line": None,
            "error": None,
        }

        writer: asyncio.StreamWriter | None = None
        try:
            port = get_host_port(host_data)
            result["port"] = port
            ssl_context = ssl.create_default_context()
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=ssl_context,
                    server_hostname=host,
                ),
                timeout=2,
            )
            request = (
                f"CONNECT example.com:443 HTTP/1.1\r\n"
                f"Host: example.com:443\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout=2)
            status_line_bytes = await asyncio.wait_for(
                _reader.readline(),
                timeout=5,
            )
            status_line = status_line_bytes.decode("iso-8859-1", "replace").strip()
            result["status_line"] = status_line
            status_match = re.match(
                r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$",
                status_line,
            )
            if status_match is None:
                raise ValueError("proxy returned a non-HTTP response")

            status_code = int(status_match.group(1))
            result["status_code"] = status_code
            result["status"] = "responded"
            if status_code == 407:
                result["ok"] = True
            elif status_code == 200:
                result["error"] = "proxy allowed CONNECT without authentication"
            else:
                reason = status_match.group(2) or "unexpected proxy response"
                result["error"] = f"HTTP {status_code} {reason}"
        except Exception as error:
            result["error"] = str(error) or error.__class__.__name__
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        set_cached_health_result("proxy_request", host, result)
        self.write(result)

    def get_allowed_health_host(self) -> dict | None:
        host = self.get_query_argument("host", "")
        host_data = find_host_data(self.hosts_data, host)
        if host_data is None:
            self.set_status(400)
            self.finish({"error": "host is not allowed"})
            return None
        return host_data


class HealthPingHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.require_authenticated_credentials()
        if self.authenticated_credentials is None:
            return

    async def get(self):
        host_data = self.get_allowed_health_host()
        if host_data is None:
            return

        host = host_data["host"]
        cached_result = get_cached_health_result("ping", host)
        if cached_result is not None:
            self.write(cached_result)
            return

        result: dict[str, object] = {
            "ok": False,
            "host": host,
            "status": "error",
            "packet_loss_percent": None,
            "rtt_avg_ms": None,
            "error": None,
        }

        try:
            ping_result = await run_ping(host)
            result.update(ping_result)
        except Exception as error:
            result["error"] = str(error) or error.__class__.__name__

        set_cached_health_result("ping", host, result)
        self.write(result)

    def get_allowed_health_host(self) -> dict | None:
        host = self.get_query_argument("host", "")
        host_data = find_host_data(self.hosts_data, host)
        if host_data is None:
            self.set_status(400)
            self.finish({"error": "host is not allowed"})
            return None
        return host_data


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


def find_host_data(hosts_data: list[dict], host: str) -> dict | None:
    if not host:
        return None

    for item in hosts_data:
        if item.get("host") == host:
            return item

    return None


def get_selected_host_data(hosts_data: list[dict]) -> dict | None:
    for item in hosts_data:
        if item.get("selected"):
            return item

    return hosts_data[0] if hosts_data else None


def order_selected_first(
    hosts_data: list[dict],
    values: list[str],
    selected_host: dict | None,
) -> list[str]:
    if selected_host is None or selected_host not in hosts_data:
        return values

    selected_index = hosts_data.index(selected_host)
    if selected_index >= len(values):
        return values

    selected_value = values[selected_index]
    return [selected_value] + [
        value
        for index, value in enumerate(values)
        if index != selected_index
    ]


def get_host_port(host_data: dict, default_port: int = 443) -> int:
    return int(host_data.get("port", default_port))


def get_cached_health_result(check_name: str, host: str) -> dict[str, object] | None:
    key = (check_name, host)
    cached = HEALTH_RESULT_CACHE.get(key)
    if cached is None:
        return None

    cached_at, result = cached
    if time.monotonic() - cached_at >= HEALTH_CACHE_TTL_SECONDS:
        HEALTH_RESULT_CACHE.pop(key, None)
        return None

    return dict(result)


def set_cached_health_result(
    check_name: str,
    host: str,
    result: dict[str, object],
) -> None:
    HEALTH_RESULT_CACHE[(check_name, host)] = (time.monotonic(), dict(result))


async def run_ping(host: str) -> dict[str, object]:
    try:
        response = await asyncio.wait_for(
            icmplib.async_ping(
                host,
                count=4,
                interval=0.2, # type: ignore
                timeout=2,
                privileged=True,
            ),
            timeout=10,
        )
    except icmplib.SocketPermissionError as error:
        return {
            "ok": False,
            "status": "error",
            "packet_loss_percent": None,
            "rtt_avg_ms": None,
            "error": f"ICMP permission denied: {error}",
        }

    packet_loss = response.packet_loss * 100
    result = {
        "ok": response.is_alive,
        "status": "responded",
        "packet_loss_percent": packet_loss,
        "rtt_avg_ms": response.avg_rtt if response.is_alive else None,
        "error": None,
    }

    if packet_loss >= 100:
        result["status"] = "error"
        result["error"] = "100% packet loss"

    return result


async def resolve_host_addresses(host: str) -> dict[str, object]:
    system_task = asyncio.create_task(resolve_host_with_system_dns(host))
    google_task = asyncio.create_task(resolve_host_with_public_dns(host, "8.8.8.8"))
    cloudflare_task = asyncio.create_task(
        resolve_host_with_public_dns(host, "1.1.1.1")
    )
    system_result, google_result, cloudflare_result = await asyncio.gather(
        system_task,
        google_task,
        cloudflare_task,
    )
    ok = bool(system_result["ok"] and google_result["ok"] and cloudflare_result["ok"])
    errors = [
        f"{name}: {result['error']}"
        for name, result in (
            ("system", system_result),
            ("8.8.8.8", google_result),
            ("1.1.1.1", cloudflare_result),
        )
        if result["error"]
    ]
    return {
        "ok": ok,
        "status": "resolved" if ok else "error",
        "system": system_result,
        "google": google_result,
        "cloudflare": cloudflare_result,
        "error": "; ".join(errors) if errors else None,
    }


async def resolve_host_with_system_dns(host: str) -> dict[str, object]:
    try:
        loop = asyncio.get_running_loop()
        addrinfo = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=5,
        )
    except Exception as error:
        return build_dns_result(False, [], str(error) or error.__class__.__name__)

    addresses = sorted({item[4][0] for item in addrinfo})
    return build_dns_result(bool(addresses), addresses, None if addresses else "no records")


async def resolve_host_with_public_dns(
    host: str,
    nameserver: str,
) -> dict[str, object]:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.lifetime = 5
    resolver.timeout = 2
    tasks = [
        asyncio.create_task(resolve_dns_record(resolver, host, dns.rdatatype.A)),
        asyncio.create_task(resolve_dns_record(resolver, host, dns.rdatatype.AAAA)),
    ]
    results = await asyncio.gather(*tasks)
    addresses = sorted({address for result in results for address in result[0]})
    errors = [result[1] for result in results if result[1]]
    if addresses:
        return build_dns_result(True, addresses, None)

    return build_dns_result(False, [], "; ".join(errors) or "no records")


async def resolve_dns_record(
    resolver: dns.asyncresolver.Resolver,
    host: str,
    record_type: dns.rdatatype.RdataType,
) -> tuple[list[str], str | None]:
    try:
        answer = await resolver.resolve(host, record_type)
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NXDOMAIN as error:
        return [], str(error) or "NXDOMAIN"
    except dns.exception.DNSException as error:
        return [], str(error) or error.__class__.__name__

    return [item.to_text() for item in answer], None


def build_dns_result(ok: bool, addresses: list[str], error: str | None) -> dict[str, object]:
    return {
        "ok": ok,
        "addresses": addresses,
        "error": error,
    }


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
    selected_host = get_selected_host_data(hosts_data)
    lines = ["# superproxy:proxylist:v1"]
    lines.extend(
        build_super_proxy_line(
            item,
            username=username,
            password=password,
            default_port=default_port,
            is_default=item is selected_host,
        )
        for item in hosts_data
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
    title = str(host_data.get("title") or host_data.get("code") or host)
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
    selected_host = get_selected_host_data(hosts_data)
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
        "mode": build_foxy_proxy_mode(proxies, hosts_data, selected_host),
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


def build_foxy_proxy_mode(
    proxies: list[dict],
    hosts_data: list[dict],
    selected_host: dict | None,
) -> str:
    if not proxies:
        return ""

    selected_proxy = proxies[0]
    if selected_host is not None and selected_host in hosts_data:
        selected_index = hosts_data.index(selected_host)
        if selected_index < len(proxies):
            selected_proxy = proxies[selected_index]
    return f"{selected_proxy['hostname']}:{selected_proxy['port']}"


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
    selected_host = get_selected_host_data(hosts_data)
    proxy_names = [
        build_shadowrocket_proxy_name(item, index)
        for index, item in enumerate(hosts_data, start=1)
    ]
    ordered_proxy_names = order_selected_first(hosts_data, proxy_names, selected_host)
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
            f"PROXY = select, {', '.join(ordered_proxy_names)}, DIRECT",
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
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "img-src 'self'",
            "navigate-to 'self' tg:",
            "object-src 'none'",
            "script-src 'self'",
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


def get_error_page_copy(status_code: int) -> tuple[str, str]:
    if status_code in ERROR_PAGE_COPY:
        return ERROR_PAGE_COPY[status_code]
    if status_code >= 500:
        return (
            "Внутренняя ошибка",
            "Запрос не удалось обработать. Попробуйте повторить позже.",
        )
    return ("Ошибка запроса", "Запрос завершился с ошибкой.")


def log_request_error(
    handler: tornado.web.RequestHandler,
    status_code: int,
    exc_info,
) -> None:
    client = get_access_log_client(handler)
    error = "-"
    if exc_info:
        error = str(exc_info[1]) or exc_info[0].__name__

    ERROR_LOG.error(
        "request_failed status=%d method=%s uri=%s ip=%s user=%s os=%s browser=%s device=%s error=%s",
        status_code,
        handler.request.method,
        handler.request.uri,
        get_access_log_ip(handler),
        get_access_log_username(handler),
        format_log_value(client.os),
        format_log_value(client.browser),
        format_log_value(client.device),
        format_log_value(error),
        exc_info=exc_info,
    )


def set_client_hint_headers(handler: tornado.web.RequestHandler) -> None:
    handler.set_header("Accept-CH", CLIENT_HINT_HEADER_VALUE)
    handler.set_header("Critical-CH", CLIENT_HINT_HEADER_VALUE)
    append_vary_header(handler, CLIENT_HINT_HEADERS)


def append_vary_header(
    handler: tornado.web.RequestHandler,
    values: tuple[str, ...],
) -> None:
    existing = handler._headers.get("Vary")
    vary_values = []
    seen = set()
    if existing:
        for value in existing.split(","):
            normalized = value.strip()
            if normalized:
                seen.add(normalized.lower())
                vary_values.append(normalized)

    for value in values:
        if value.lower() not in seen:
            vary_values.append(value)
            seen.add(value.lower())

    if vary_values:
        handler.set_header("Vary", ", ".join(vary_values))


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
    configure_tagged_logger(
        ERROR_LOG,
        tag="error",
        log_file=log_dir / "error.log",
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
        client = get_access_log_client(handler)
        log_method(
            "%d %s %s ip=%s user=%s os=%s browser=%s device=%s %.2fms",
            status,
            handler.request.method,
            handler.request.uri,
            get_access_log_ip(handler),
            get_access_log_username(handler),
            format_log_value(client.os),
            format_log_value(client.browser),
            format_log_value(client.device),
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


def get_access_log_client(handler: tornado.web.RequestHandler) -> AccessLogClient:
    headers = handler.request.headers
    user_agent = parse_user_agent(headers.get("User-Agent", ""))
    os_name = format_name_version(
        user_agent.os.family,
        user_agent.os.version_string,
    )
    browser = format_name_version(
        user_agent.browser.family,
        user_agent.browser.version_string,
    )
    device = get_user_agent_device(user_agent)

    platform = parse_client_hint_string(headers.get("Sec-CH-UA-Platform"))
    platform_version = parse_client_hint_string(
        headers.get("Sec-CH-UA-Platform-Version")
    )
    if platform:
        os_name = format_name_version(platform, platform_version)

    hint_browser = get_client_hint_browser(
        headers.get("Sec-CH-UA-Full-Version-List") or headers.get("Sec-CH-UA")
    )
    if hint_browser:
        browser = hint_browser

    model = parse_client_hint_string(headers.get("Sec-CH-UA-Model"))
    mobile = headers.get("Sec-CH-UA-Mobile")
    if model:
        device = model
    elif mobile == "?1":
        device = "mobile"
    elif mobile == "?0" and device == "-":
        device = "desktop"

    return AccessLogClient(
        os=os_name or "-",
        browser=browser or "-",
        device=device or "-",
    )


def get_user_agent_device(user_agent) -> str:
    if user_agent.is_bot:
        return "bot"
    if user_agent.is_tablet:
        return "tablet"
    if user_agent.is_mobile:
        return "mobile"
    if user_agent.is_pc:
        return "desktop"
    if user_agent.device.family and user_agent.device.family != "Other":
        return user_agent.device.family
    return "-"


def format_name_version(name: str, version: str | None) -> str:
    if not name or name == "Other":
        return "-"
    if version:
        return f"{name} {version}"
    return name


def parse_client_hint_string(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def get_client_hint_browser(value: str | None) -> str:
    if not value:
        return ""

    brands: list[tuple[str, str]] = []
    for match in re.finditer(r'"([^"]+)";v="([^"]+)"', value):
        brand, version = match.groups()
        if "brand" in brand.lower():
            continue
        brands.append((brand, version))

    if not brands:
        return ""

    preferred_names = (
        "Google Chrome",
        "Microsoft Edge",
        "Opera",
        "Brave",
        "Chromium",
    )
    by_name = {brand: version for brand, version in brands}
    for name in preferred_names:
        if name in by_name:
            return format_name_version(name, by_name[name])

    brand, version = brands[0]
    return format_name_version(brand, version)


def format_log_value(value: str) -> str:
    if not value or value == "-":
        return "-"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def make_app(
    data_dir: pathlib.Path,
    config_dir: pathlib.Path,
    state_dir: pathlib.Path,
    cookie_secret: str,
) -> tornado.web.Application:
    hosts_data = json.loads((config_dir / "hosts.json").read_text())
    admin_user = read_optional_text(config_dir / "admin.txt") or None

    session_store = SessionStore(SESSION_TTL_SECONDS)
    ban_store = PersistentBanStore(
        BAN_TTL_SECONDS,
        FAILURE_WINDOW_SECONDS,
        state_dir / "bans.json",
    )
    return PxManagerApplication(
        [
            (r"/", IndexHandler),
            (r"/admin", AdminHandler),
            (r"/doc", DocHandler),
            (r"/health", HealthPageHandler),
            (r"/logout", LogoutHandler),
            (r"/favicon.ico", FaviconHandler),
            (r"/robots.txt", RobotsHandler),
            (r"/api", ApiHandler),
            (r"/api/health/connect", HealthConnectHandler),
            (r"/api/health/dns", HealthDnsHandler),
            (r"/api/health/head", HealthHeadHandler),
            (r"/api/health/ping", HealthPingHandler),
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
        default_handler_class=ErrorPageHandler,
        static_path=str(resource_path("static")),
        template_path=str(resource_path("templates")),
        data_dir=data_dir,
        admin_user=admin_user,
        password_store=PasswordStore.from_file(config_dir / "passwd.json"),
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
    "--config-dir",
    type=click.Path(
        exists=True,
        dir_okay=True,
        file_okay=False,
        path_type=pathlib.Path,
    ),
    default=cur_dir / "data",
    help="Directory with hosts.json, admin.txt and passwd.json.",
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
    help="Directory for access/auth/ban/error log files.",
)
@click.option(
    "--state-dir",
    type=click.Path(
        dir_okay=True,
        file_okay=False,
        path_type=pathlib.Path,
    ),
    default=cur_dir / "state",
    show_default=True,
    help="Directory for persistent runtime state.",
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
    config_dir: pathlib.Path,
    log_dir: pathlib.Path,
    state_dir: pathlib.Path,
    host: str,
    port: int,
    cors_origin: tuple[str, ...],
    cookie_secret: str | None,
):
    if not cookie_secret:
        cookie_secret = secrets.token_urlsafe(32)

    configure_logging(log_dir)
    app = make_app(data_dir, config_dir, state_dir, cookie_secret)
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
