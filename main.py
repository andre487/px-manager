import base64
import json
import pathlib
import secrets
import sys

import click
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.web
from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, VerificationError


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


class BaseHandler(tornado.web.RequestHandler):
    @property
    def password_store(self) -> PasswordStore:
        return self.application.settings["password_store"]

    def get_current_user(self):
        user = self.get_secure_cookie("user")
        if user is None:
            return None
        return tornado.escape.to_unicode(user)

    def verify_basic_auth(self) -> str | None:
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
            return username
        return None


class IndexHandler(BaseHandler):
    def get(self):
        self.render("index.html", error=None)

    def post(self):
        username = self.get_body_argument("username", "")
        password = self.get_body_argument("password", "")

        if not self.password_store.verify(username, password):
            self.set_status(401)
            self.render("index.html", error="Invalid login or password")
            return

        self.set_secure_cookie(
            "user",
            username,
            httponly=True,
            samesite="Strict",
        )
        self.redirect("/")


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect("/")


class FaviconHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Content-Type", "image/x-icon")
        self.set_header("Cache-Control", "public, max-age=31536000, immutable")
        self.write(resource_path("static", "favicon.ico").read_bytes())


class ApiHandler(BaseHandler):
    def prepare(self):
        self.authenticated_user = self.current_user or self.verify_basic_auth()
        if self.authenticated_user is None:
            self.set_status(401)
            self.set_header("WWW-Authenticate", 'Basic realm="px-manager"')
            self.finish({"error": "authentication required"})

    def get(self):
        self.write(
            {
                "ok": True,
                "user": self.authenticated_user,
            }
        )


def make_app(passwd_file: pathlib.Path, cookie_secret: str) -> tornado.web.Application:
    return tornado.web.Application(
        [
            (r"/", IndexHandler),
            (r"/logout", LogoutHandler),
            (r"/favicon.ico", FaviconHandler),
            (r"/api", ApiHandler),
        ],
        cookie_secret=cookie_secret,
        static_path=str(resource_path("static")),
        template_path=str(resource_path("templates")),
        password_store=PasswordStore.from_file(passwd_file),
    )


@click.command()
@click.option(
    "--passwd-file",
    type=click.Path(
        exists=True, dir_okay=False, file_okay=True, path_type=pathlib.Path
    ),
    required=True,
)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8888, show_default=True, type=int)
@click.option(
    "--cookie-secret",
    envvar="PX_MANAGER_COOKIE_SECRET",
    help="Secret used to sign session cookies. Defaults to a random startup secret.",
)
def main(
    passwd_file: pathlib.Path,
    host: str,
    port: int,
    cookie_secret: str | None,
):
    if not cookie_secret:
        cookie_secret = secrets.token_urlsafe(32)

    app = make_app(passwd_file, cookie_secret)
    server = tornado.httpserver.HTTPServer(app)
    server.listen(port, address=host)
    click.echo(f"Listening on http://{host}:{port}")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
