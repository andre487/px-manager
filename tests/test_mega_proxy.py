import unittest

from main import build_mega_proxy_config, build_mega_proxy_profile


class MegaProxyExportTest(unittest.TestCase):
    def test_exports_schema_version_seven_and_global_settings(self):
        config = build_mega_proxy_config(
            [{"host": "proxy.example", "title": "Example", "code": "NL"}],
            username="alice",
            password="secret",
            default_port="443",
        )

        self.assertEqual("dev.megaproxy.config", config["schema"])
        self.assertEqual(7, config["version"])
        self.assertEqual(config["profiles"][0]["id"], config["activeProfileId"])
        self.assertEqual("DEFAULT", config["tls"]["fingerprint"])
        self.assertEqual("AUTO", config["ssh"]["authMode"])
        self.assertEqual("DISABLED", config["failover"]["mode"])
        self.assertTrue(config["routing"]["routeAllApps"])

    def test_profile_id_survives_password_and_metadata_changes(self):
        host = {"host": "Proxy.Example", "port": 8443, "title": "Old", "code": "NL"}
        original = build_mega_proxy_profile(
            host, username="alice", password="old", default_port="443", color=0
        )
        changed = build_mega_proxy_profile(
            {**host, "title": "New", "code": "DE"},
            username="alice",
            password="new",
            default_port="443",
            color=4,
        )

        self.assertEqual(original["id"], changed["id"])
        self.assertNotEqual(original["proxy"]["password"], changed["proxy"]["password"])

    def test_different_users_get_different_profile_ids(self):
        host = {"host": "proxy.example"}
        alice = build_mega_proxy_profile(
            host, username="alice", password="secret", default_port="443", color=0
        )
        bob = build_mega_proxy_profile(
            host, username="bob", password="secret", default_port="443", color=0
        )

        self.assertNotEqual(alice["id"], bob["id"])


if __name__ == "__main__":
    unittest.main()
