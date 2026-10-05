import pathlib
import tempfile

from tornado.testing import AsyncHTTPTestCase

from main import make_app, resource_path


class NoIndexTest(AsyncHTTPTestCase):
    def get_app(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = pathlib.Path(self.directory.name)
        (root / "hosts.json").write_text("[]")
        (root / "passwd.json").write_text("{}")
        return make_app(root, root, root, root, "test-secret")

    def test_disables_indexing_everywhere(self):
        for path, status in (
            ("/", 200),
            ("/admin", 302),
            ("/api", 403),
            ("/robots.txt", 200),
            ("/favicon.ico", 200),
            ("/static/common.css", 200),
            ("/static/missing.css", 404),
            ("/missing", 404),
        ):
            with self.subTest(path=path):
                response = self.fetch(path, follow_redirects=False)
                self.assertEqual(status, response.code)
                self.assertEqual("noindex, nofollow", response.headers["X-Robots-Tag"])

        self.assertEqual(
            b"User-agent: *\nDisallow: /\n", self.fetch("/robots.txt").body
        )
        for template in resource_path("templates").glob("*.html"):
            with self.subTest(template=template.name):
                self.assertIn(
                    '<meta name="robots" content="noindex, nofollow">',
                    template.read_text(),
                )
