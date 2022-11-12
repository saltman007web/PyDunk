import srp
import plistlib as plist
from base64 import b64encode, b64decode
import requests
import json
import pbkdf2
import hashlib

# Constants
DEBUG = False  # Allows using a proxy for debugging (disables SSL verification)
# Server to use for anisette generation
ANISETTE = "https://sign.rheaa.xyz/"
GSA = "https://gsa.apple.com/grandslam/GsService2"  # Self explanatory

# Allows you to use a proxy for debugging
if DEBUG:
    # mitmproxy
    proxies = {
        "http": "http://localhost:8080",
        "https": "http://localhost:8080",
    }
else:
    proxies = {}

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()


def generate_anisette() -> dict:
    r = requests.get(ANISETTE, verify=False if DEBUG else True, proxies=proxies)
    r = json.loads(r.text)
    return r


def generate_cpd(anisette: dict) -> dict:
    return {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        # I've chosen to match the AltServer implementation
        # Not sure what these are for, needs some investigation
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
        # Not included, but I've also seen:
        # 'capp': 'AppStore',
        # 'dc': '#d4c5b3',
        # 'dec': '#e1e4e3',
        # 'prtn': 'ME349',
        # 'AppleIDClientIdentifier': 'D4B7512F-E841-4AEA-A569-4F1E84738182',
        # 'X-Apple-App-Info': 'com.apple.gs.xcode.auth',
        # Current Time
        "X-Apple-I-Client-Time": anisette["X-Apple-I-Client-Time"],
        "X-Apple-I-TimeZone": anisette["X-Apple-I-TimeZone"],
        # Locale
        # Some implementations only use this for locale
        "loc": anisette["X-Apple-Locale"],
        "X-Apple-Locale": anisette["X-Apple-Locale"],
        # Anisette
        "X-Apple-I-MD": anisette["X-Apple-I-MD"],  # 'One Time Password'
        # 'Local User ID'
        "X-Apple-I-MD-LU": anisette["X-Apple-I-MD-LU"],
        "X-Apple-I-MD-M": anisette["X-Apple-I-MD-M"],  # 'Machine ID'
        # 'Routing Info', some implementations leave this as a string
        "X-Apple-I-MD-RINFO": int(anisette["X-Apple-I-MD-RINFO"]),
        # Device information
        # 'Device Unique Identifier'
        "X-Mme-Device-Id": anisette["X-Mme-Device-Id"],
        # 'Device Serial Number'
        "X-Apple-I-SRL-NO": anisette["X-Apple-I-SRL-NO"],
    }


def authenticated_request(parameters, anisette) -> dict:
    body = {
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": generate_cpd(anisette),
        },
    }
    body["Request"].update(parameters)
    # print(plist.dumps(body).decode('utf-8'))

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": anisette["X-MMe-Client-Info"],
    }

    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,  # TODO: Verify Apple's self-signed cert
        proxies=proxies,
    )

    return plist.loads(resp.content)["Response"]


def check_error(r):
    # Check for an error code
    status = r["Status"]
    if status["ec"] != 0:
        print(f"Error {status['ec']}: {status['em']}")
        return True
    return False


def encrypt_password(password: str, salt: bytes, iterations: int) -> bytes:
    p = hashlib.sha256(password.encode("utf-8")).digest()
    return pbkdf2.PBKDF2(p, salt, iterations, hashlib.sha256).read(32)


def authenticate(username, password):
    anisette = generate_anisette()

    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()

    r = authenticated_request(
        {
            "A2k": A,
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        },
        anisette,
    )

    # Check for an error code
    if check_error(r):
        return

    if r["sp"] != "s2k":
        print(f"This implementation only supports s2k. Server returned {r['sp']}")
        return

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"])  # type: ignore

    M = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if M is None:
        print("Failed to process challenge")
        return

    r = authenticated_request(
        {
            "c": r["c"],
            "M1": M,
            "u": username,
            "o": "complete",
        },
        anisette,
    )

    if check_error(r):
        return
    print(r)

    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        print("Failed to verify session")
        return


if __name__ == "__main__":
    # Try and get the username and password from environment variables
    import os

    username = os.environ.get("APPLE_ID")
    password = os.environ.get("APPLE_ID_PASSWORD")
    # If they're not set, prompt the user
    if username is None:
        username = input("Apple ID: ")
    if password is None:
        import getpass

        password = getpass.getpass("Password: ")

    authenticate(username, password)
