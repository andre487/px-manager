import secrets


def main():
    print("PX_MANAGER_COOKIE_SECRET=" + secrets.token_urlsafe(48))


if __name__ == "__main__":
    main()
