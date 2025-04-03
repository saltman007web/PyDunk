from pprint import pp

from .auth import GSAuth
from .anisette import Anisette
from .models import GSAuthToken, GSAuthTokens

from requests import Response


def main() -> tuple[GSAuth, dict | tuple[dict, Response | None]]:
    import os
    from getpass import getpass
    username = os.environ.get("APPLE_ID")
    if not username: username = input("Apple ID: ")
    password = os.environ.get("APPLE_ID_PASSWORD")
    if not password: password = getpass("Password: ")
    serial = os.environ.get("APPLE_SERIAL")
    ani = Anisette(serial=serial)
    auth = GSAuth(ani)
    return (auth, auth.fetch_xcode_token(username, password))


m = main()
a = m[0]
def parse_tokens(data: dict):
    for k, v in data.items():
        print(f"{k}: {v['expiry']}\n{v['token']}")

tokens = m[1]['t'] if isinstance(m[1], dict) else m[1][0]['t']
#parse_tokens(tokens)

x = m[1][1]
