import base64
import json
import pathlib
import secrets
import sys
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode

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


class BaseHandler(tornado.web.RequestHandler):
    @property
    def password_store(self) -> PasswordStore:
        return self.application.settings["password_store"]

    @property
    def session_store(self) -> SessionStore:
        return self.application.settings["session_store"]

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

    def verify_basic_auth(self) -> tuple[str, str] | None:
        auth_header = self.request.headers.get("Authorization", "")
        auth_type, _, credentials = auth_header.partition(" ")
        if auth_type.lower() != "basic" or not credentials:
            return None

        try:
            decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
        except ValueError, UnicodeDecodeError:
            return None

        username, separator, password = decoded.partition(":")
        if not separator:
            return None

        if self.password_store.verify(username, password):
            return username, password
        return None

    def get_authenticated_credentials(self) -> tuple[str, str] | None:
        session = self.get_session()
        if session is not None:
            return session.username, session.password

        return self.verify_basic_auth()


class IndexHandler(BaseHandler):
    def get(self):
        self.render(
            "index.html",
            error=None,
            message=read_message(self.data_dir),
            is_admin=self.is_admin,
        )

    def post(self):
        username = self.get_body_argument("username", "")
        password = self.get_body_argument("password", "")

        if not self.password_store.verify(username, password):
            self.set_status(401)
            self.render(
                "index.html",
                error="Invalid login or password",
                message=read_message(self.data_dir),
                is_admin=False,
            )
            return

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
    def get(self):
        session_id = self.get_secure_cookie(SESSION_COOKIE_NAME)
        if session_id is not None:
            self.session_store.delete(tornado.escape.to_unicode(session_id))
        self.clear_cookie(SESSION_COOKIE_NAME)
        self.clear_cookie("user")
        self.redirect("/")


class FaviconHandler(tornado.web.RequestHandler):
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
        self.render("admin.html", message=read_message(self.data_dir), saved=False)

    def post(self):
        write_message(self.data_dir, self.get_body_argument("message", ""))
        self.render("admin.html", message=read_message(self.data_dir), saved=True)


class ApiHandler(BaseHandler):
    def prepare(self):
        self.authenticated_credentials = self.get_authenticated_credentials()
        if self.authenticated_credentials is None:
            self.set_status(401)
            self.set_header("WWW-Authenticate", 'Basic realm="px-manager"')
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
        self.authenticated_credentials = self.get_authenticated_credentials()
        if self.authenticated_credentials is None:
            self.set_status(401)
            self.set_header("WWW-Authenticate", 'Basic realm="px-manager"')
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
            'attachment; filename="proxy-list.txt"',
        )
        self.write("\n".join(lines) + "\n")


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


def read_optional_text(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text().strip()


def read_message(data_dir: pathlib.Path) -> str:
    return read_optional_text(data_dir / "message.txt")


def write_message(data_dir: pathlib.Path, message: str) -> None:
    (data_dir / "message.txt").write_text(message.strip())


def make_app(data_dir: pathlib.Path, cookie_secret: str) -> tornado.web.Application:
    hosts_data = json.loads((data_dir / "hosts.json").read_text())
    admin_user = read_optional_text(data_dir / "admin.txt") or None

    session_store = SessionStore(SESSION_TTL_SECONDS)
    return tornado.web.Application(
        [
            (r"/", IndexHandler),
            (r"/admin", AdminHandler),
            (r"/logout", LogoutHandler),
            (r"/favicon.ico", FaviconHandler),
            (r"/api", ApiHandler),
            (r"/api/generate/proxy-list", ProxyListGenerateHandler),
        ],
        cookie_secret=cookie_secret,
        static_path=str(resource_path("static")),
        template_path=str(resource_path("templates")),
        data_dir=data_dir,
        admin_user=admin_user,
        password_store=PasswordStore.from_file(data_dir / "passwd.json"),
        hosts_data=hosts_data,
        session_store=session_store,
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
    "--cookie-secret",
    envvar="PX_MANAGER_COOKIE_SECRET",
    help="Secret used to sign session cookies. Defaults to a random startup secret.",
)
def main(
    data_dir: pathlib.Path,
    host: str,
    port: int,
    cookie_secret: str | None,
):
    if not cookie_secret:
        cookie_secret = secrets.token_urlsafe(32)

    app = make_app(data_dir, cookie_secret)
    server = tornado.httpserver.HTTPServer(app)
    server.listen(port, address=host)
    session_cleanup = tornado.ioloop.PeriodicCallback(
        app.settings["session_store"].cleanup_expired,
        SESSION_CLEANUP_INTERVAL_MS,
    )
    session_cleanup.start()
    click.echo(f"Listening on http://{host}:{port}")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
