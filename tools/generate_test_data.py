import json
import os
import pathlib

from argon2 import PasswordHasher

TEST_USERS = {
    "test": "test",
    "user": "password",
    "admin": "admin",
}

data_dir = pathlib.Path(os.path.join(os.path.dirname(__file__), "..", "data")).absolute()


def main():
    with open(data_dir / "admin.txt", "w") as f:
        f.write("admin")

    generate_passwd()
    generate_hosts()


def generate_passwd():
    ph = PasswordHasher()

    passwd_data = {}
    for name, password in TEST_USERS.items():
        passwd_data[name] = ph.hash(password)

    passwd_file = os.path.join(data_dir, "passwd.json")
    with open(passwd_file, "w") as f:
        json.dump(passwd_data, f, indent=2)


def generate_hosts():
    hosts_data = [
        {
            "host": "test1.example.com",
            "code": "AM",
            "title": "AM",
        },
        {
            "host": "test2.example.com",
            "code": "KZ",
            "title": "KZ",
        },
        {
            "host": "test3.example.com",
            "code": "RU",
            "title": "RU",
        },
    ]
    hosts_file = os.path.join(data_dir, "hosts.json")
    with open(hosts_file, "w") as f:
        json.dump(hosts_data, f, indent=2)


if __name__ == "__main__":
    main()
