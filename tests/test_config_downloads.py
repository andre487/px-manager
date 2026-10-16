import json
import pathlib
import tempfile
from unittest.mock import patch

from tornado.testing import AsyncHTTPTestCase
from tornado.web import create_signed_value

from main import SESSION_COOKIE_NAME, make_app


class ConfigDownloadTest(AsyncHTTPTestCase):
    def get_app(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "hosts.json").write_text(
            json.dumps(
                [
                    {"host": "one.example", "title": "One"},
                    {"host": "two.example", "port": 8443, "selected": True},
                ]
            )
        )
        (root / "passwd.json").write_text("{}")
        return make_app(root, root, root, root, "test-secret")

    def test_all_downloads(self):
        session = self._app.settings["session_store"].create("alice", "s@cret")
        cookie = create_signed_value(
            "test-secret", SESSION_COOKIE_NAME, session
        ).decode()
        with (
            patch("main.get_tls_fingerprint", return_value="ab" * 20) as fingerprint,
            patch(
                "main.socket.create_connection",
                side_effect=AssertionError("unexpected network"),
            ),
        ):
            for name, extension, content_type in (
                ("proxy-list", "txt", "text/plain"),
                ("super-proxy", "txt", "text/plain"),
                ("foxy-proxy", "json", "application/json"),
                ("mega-proxy", "json", "application/json"),
                ("shadowrocket", "conf", "text/plain"),
            ):
                with self.subTest(name=name):
                    response = self.fetch(
                        "/api/generate/" + name,
                        headers={"Cookie": f"{SESSION_COOKIE_NAME}={cookie}"},
                    )
                    self.assertEqual(200, response.code)
                    self.assertEqual(
                        content_type + "; charset=utf-8",
                        response.headers["Content-Type"],
                    )
                    self.assertIn(
                        f'filename="alice-{name}.{extension}"',
                        response.headers["Content-Disposition"],
                    )
                    self.assertIn(b"one.example", response.body)
                    self.assertIn(b"two.example", response.body)
                    if extension == "json":
                        json.loads(response.body)
                    if name == "super-proxy":
                        self.assertIn(
                            ("?fingerprint=" + "ab" * 20).encode(), response.body
                        )
                        self.assertIn(b"@two.example:8443?fingerprint=", response.body)
                        self.assertTrue(response.body.endswith(b'"two.example" *\n'))
            self.assertEqual(2, fingerprint.call_count)
