import json
import os

from argon2 import PasswordHasher

TEST_USERS = {
    "test": "test",
    "user": "password",
    "admin": "admin",
}


def main():
    ph = PasswordHasher()

    passwd_data = {}
    for name, password in TEST_USERS.items():
        passwd_data[name] = ph.hash(password)

    passwd_file = os.path.join(os.path.dirname(__file__), "..", "data", "passwd.json")
    with open(passwd_file, "w") as f:
        json.dump(passwd_data, f, indent=2)


if __name__ == "__main__":
    main()
