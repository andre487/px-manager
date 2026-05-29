import json
import pathlib
import sys

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error


def main():
    users = json.load(sys.stdin)
    existing_path = pathlib.Path(sys.argv[1])

    try:
        existing = json.loads(existing_path.read_text())
    except FileNotFoundError:
        existing = {}

    hasher = PasswordHasher()
    passwd = {}

    for user in users:
        name = user["name"]
        password = user["password"]
        current_hash = existing.get(name)

        if current_hash:
            try:
                if hasher.verify(current_hash, password):
                    passwd[name] = current_hash
                    continue
            except Argon2Error:
                pass

        passwd[name] = hasher.hash(password)

    print(json.dumps(passwd, indent=2))


if __name__ == "__main__":
    main()
