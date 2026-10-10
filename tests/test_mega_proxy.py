import json
import pathlib
import tempfile
import unittest

from jsonschema import Draft202012Validator
from tornado.testing import AsyncHTTPTestCase
from tornado.web import create_signed_value

from main import (
    SESSION_COOKIE_NAME,
    build_mega_proxy_config,
    build_mega_proxy_profile,
    make_app,
)


class MegaProxyExportTest(unittest.TestCase):
    def test_exports_schema_version_eight_and_global_settings(self):
        config = build_mega_proxy_config(
            [{"host": "proxy.example", "title": "Example", "code": "NL"}],
            username="alice",
            password="secret",
            default_port="443",
        )

        self.assertEqual("net.megaproxy487.config", config["schema"])
        self.assertEqual(8, config["version"])
        self.assertEqual(config["profiles"][0]["id"], config["activeProfileId"])
        self.assertEqual("DEFAULT", config["tls"]["fingerprint"])
        self.assertEqual("AUTO", config["ssh"]["authMode"])
        self.assertEqual("DISABLED", config["failover"]["mode"])
        self.assertTrue(config["routing"]["routeAllApps"])
        self.assertNotIn("subscription", config)

    def test_generated_json_matches_official_schema(self):
        schema = json.loads(
            (
                pathlib.Path(__file__).parent / "schemas" / "megaproxy-v8.schema.json"
            ).read_text()
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for hosts in (
            [{"host": "proxy.example"}],
            [
                {
                    "host": "192.0.2.1",
                    "port": "8443",
                    "code": "nl",
                    "title": "Нидерланды",
                },
                {
                    "host": "chain.example",
                    "port": 65535,
                    "code": "TR",
                    "selected": True,
                    "probe_resistance_enabled": True,
                },
                {
                    "host": "plain.example",
                    "code": "invalid",
                    "probe_resistance_enabled": False,
                },
            ],
        ):
            with self.subTest(hosts=hosts):
                config = build_mega_proxy_config(
                    hosts,
                    username="alice",
                    password="secret",
                    default_port="443",
                    subscription={
                        "url": "https://configs.example/api/config",
                        "fallbackUrls": ["https://backup.example:8443/api/config"],
                        "intervalMinutes": 60,
                        "enabled": True,
                    },
                )
                validator.validate(json.loads(json.dumps(config, ensure_ascii=False)))

    def test_knock_host_is_enabled_only_for_masked_proxies(self):
        for enabled in (None, False, True):
            with self.subTest(enabled=enabled):
                host = {"host": "proxy.example"}
                if enabled is not None:
                    host["probe_resistance_enabled"] = enabled
                config = build_mega_proxy_config(
                    [host], username="alice", password="secret", default_port="443"
                )
                self.assertEqual(
                    "px-knock.jethelix.ru" if enabled else "",
                    config["profiles"][0]["browser"]["knockHost"],
                )

    def test_profile_id_survives_endpoint_credentials_and_metadata_changes(self):
        host = {
            "profile_id": "primary-netherlands",
            "host": "old.example",
            "port": 8443,
            "title": "Old",
            "code": "NL",
        }
        original = build_mega_proxy_profile(
            host, username="alice", password="old", default_port="443", color=0
        )
        changed = build_mega_proxy_profile(
            {**host, "host": "new.example", "port": 443, "title": "New", "code": "DE"},
            username="new-login",
            password="new",
            default_port="443",
            color=4,
        )

        self.assertEqual(original["id"], changed["id"])
        self.assertNotEqual(original["proxy"]["password"], changed["proxy"]["password"])

    def test_different_users_get_the_same_profile_id(self):
        host = {"profile_id": "shared-proxy", "host": "proxy.example"}
        alice = build_mega_proxy_profile(
            host, username="alice", password="secret", default_port="443", color=0
        )
        bob = build_mega_proxy_profile(
            host, username="bob", password="secret", default_port="443", color=0
        )

        self.assertEqual(alice["id"], bob["id"])

    def test_duplicate_stable_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "profile IDs must be unique"):
            build_mega_proxy_config(
                [
                    {"profile_id": "same", "host": "one.example"},
                    {"profile_id": "same", "host": "two.example"},
                ],
                username="alice",
                password="secret",
                default_port="443",
            )

    def test_chain_profile_uses_explicit_exit_country_code(self):
        profile = build_mega_proxy_profile(
            {
                "host": "armenia-via-turkey.example",
                "title": "TR Chain",
                "code": "TR",
            },
            username="alice",
            password="secret",
            default_port="443",
            color=0,
        )

        self.assertEqual("TR", profile["countryCode"])


class MegaProxySubscriptionTest(AsyncHTTPTestCase):
    def get_app(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "hosts.json").write_text('[{"host": "proxy.example"}]')
        (root / "passwd.json").write_text("{}")
        self.subscription = {
            "url": "https://configs.example/api/config",
            "fallbackUrls": ["https://backup.example:8443/api/config"],
            "intervalMinutes": 120,
            "enabled": True,
        }
        (root / "subscription.json").write_text(json.dumps(self.subscription))
        return make_app(root, root, root, root, "test-secret")

    def test_export_uses_inventory_subscription_and_session_credentials(self):
        session_id = self._app.settings["session_store"].create("alice", "secret")
        cookie = create_signed_value(
            "test-secret", SESSION_COOKIE_NAME, session_id
        ).decode()
        response = self.fetch(
            "/api/generate/mega-proxy",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={cookie}"},
        )
        self.assertEqual(200, response.code)
        config = json.loads(response.body)
        self.assertEqual(
            {**self.subscription, "username": "alice", "password": "secret"},
            config["subscription"],
        )
        self.assertEqual(
            config["profiles"][0]["proxy"]["username"],
            config["subscription"]["username"],
        )
        self.assertEqual(
            config["profiles"][0]["proxy"]["password"],
            config["subscription"]["password"],
        )
        self.assertEqual(
            self.subscription, self._app.settings["mega_proxy_subscription"]
        )


if __name__ == "__main__":
    unittest.main()
