import hmac
import urllib3
from pprint import pp
import plistlib as plist
from hashlib import sha256
from base64 import b64encode

from .anisette import Anisette
from .xcode import XcodeSession
from .common import SessionProvider

from requests import Session, Response
from srp._pysrp import User, SHA256, NG_2048, rfc5054_enable, no_username_in_x
from pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7 as padPKCS7

rfc5054_enable()
no_username_in_x()

urllib3.disable_warnings()

def check_error(r: dict) -> bool:
    status = r["Status"] if "Status" in r else r
    if status["ec"] != 0:
        print(f"Error {status['ec']}: {status['em']}")
        return True
    return False

def encrypt_password(password: str, salt: bytes, iterations: int) -> bytes:
    p = sha256(password.encode("utf-8")).digest()
    return PBKDF2(p, salt, iterations, sha256).read(32)

def create_session_key(usr: User, name: str) -> bytes:
    k = usr.get_session_key()
    if k is None: raise ValueError("Expected a session key from User object!")
    return hmac.new(k, name.encode(), sha256).digest()

def decrypt_cbc(usr: User, data: bytes) -> bytes:
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv  = create_session_key(usr, "extra data iv:")
    extra_data_iv  = extra_data_iv[:16]

    cipher = Cipher(AES(extra_data_key), CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    padder = padPKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()

def decrypt_gcm(data: bytes, session_key: bytes) -> bytes | None:
    if not session_key or len(data) < 35: return
    version_size, iv_size, tag_size = 3, 16, 16
    decrypted_size = len(data) - (version_size + iv_size + tag_size)
    if decrypted_size <= 0: return
    version = data[:version_size]
    iv = data[version_size:version_size + iv_size]
    cipher = data[version_size + iv_size:-tag_size]
    tag = data[-tag_size:]
    try: return AESGCM(session_key).decrypt(iv, cipher + tag, version)
    except: return


class GSAuth(SessionProvider):
    def __init__(
        self,
        anisette: Anisette | None = None,
        session: Session | None = None,
    ):
        super().__init__(session)

        if anisette is None: anisette = Anisette(session=self.session)
        self.anisette = anisette
        self.session = self.anisette.session

    def authenticated_request(self, params: dict) -> dict:
        url = "https://gsa.apple.com/GsService2"
        body = {
            "Header": {
                "Version": "1.0.1",
            },
            "Request": {
                "cpd": self.anisette.cpd
            },
        }

        body["Request"].update(params)
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": self.anisette.client,
            "X-Apple-I-SRL-NO": self.anisette.serial,
        }
        resp = self.session.post(
            url,
            headers=headers,
            data=plist.dumps(body),
            verify=False,
            timeout=5,
        )
        return plist.loads(resp.content)["Response"]

    def _auth_headers(self, identity_token: str) -> dict[str, str]:
        return {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
        }

    def trusted_2fa(self, dsid: str, idms_token: str) -> Response | None:
        identity_token = b64encode((f"{dsid}:{idms_token}".encode())).decode()
        headers = self._auth_headers(identity_token)
        headers |= self.anisette.headers(True)
        self.session.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=headers,
            verify=False,
            timeout=10,
        )

        code = int(input("Enter 2FA code: "))
        headers["security-code"] = f"{code}"

        resp = self.session.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=headers,
            verify=False,
            timeout=10,
        )
        r = plist.loads(resp.content)
        if check_error(r): return
        print("2FA successful")
        return r

    def sms_2fa(self, dsid: str, idms_token: str) -> Response | None:
        identity_token = b64encode((f"{dsid}:{idms_token}".encode())).decode()
        headers = self._auth_headers(identity_token)
        headers |= self.anisette.headers(True)
        body = {"phoneNumber": {"id": 1}, "mode": "sms"}
        self.session.put(
            "https://gsa.apple.com/auth/verify/phone/",
            data=plist.dumps(body),
            headers=headers,
            verify=False,
            timeout=5,
        )

        code = int(input("Enter 2FA code: "))
        body["securityCode"] = {"code": f"{code}"}

        resp = self.session.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            data=plist.dumps(body),
            headers=headers,
            verify=False,
            timeout=5
        )
        if resp.ok: print("2FA successful")
        return resp
    
    def authenticate(self, username: str, password: str) -> dict | tuple[dict, Response | None]:
        usr = User(username, bytes(), hash_alg=SHA256, ng_type=NG_2048)
        _, A = usr.start_authentication()

        r = self.authenticated_request({
            "A2k": A,
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        })
        if check_error(r): raise ValueError("init Response didn't return successfully")

        if r["sp"] != "s2k": raise ValueError(f"This implementation only supports s2k. Server returned {r['sp']}")
        
        usr.p = encrypt_password(password, r["s"], r["i"])
        M = usr.process_challenge(r["s"], r["B"])
        if M is None: raise ValueError(f"Failed to process challenge for {username!r}!")
        r = self.authenticated_request({
            "c": r["c"],
            "M1": M,
            "u": username,
            "o": "complete",
        })

        if check_error(r): raise ValueError("complete Response didn't return successfully")
        
        usr.verify_session(r["M2"])
        if not usr.authenticated(): raise ValueError("Failed to veryfy session")

        spd_bytes = decrypt_cbc(usr, r["spd"])
        spd = plist.loads(plist.PLISTHEADER + spd_bytes)

        t = r["Status"]["au"] if "au" in r["Status"] else ""
        if t == "trustedDeviceSecondaryAuth":
            which = input("Type SMS to use SMS: ")
            if which == "SMS":
                auth = self.sms_2fa
            else:
                auth = self.trusted_2fa
        elif t == "secondaryAuth":
            print("SMS authentication required")
            auth = self.sms_2fa
        elif t != "":
            raise ValueError(f"Unknown auth value {t}")
        else:
            print("Assuming 2FA is not required")
            return spd
        return (spd, auth(spd['adsid'], spd['GsIdmsToken']))

    def make_app_checksum(self, app_name: str, session_key: bytes | None, dsid: str | None) -> bytes | None:
        if not session_key or not dsid: return
        hmac_ctx = hmac.new(session_key, digestmod=sha256)
        for s in ["apptokens", dsid, app_name]: hmac_ctx.update(s.encode("utf-8"))
        return hmac_ctx.digest()

    def fetch_xcode_token(self, username: str, password: str):
        app = "com.apple.gs.xcode.auth"
        spd_call = self.authenticate(username, password)
        spd = spd_call if isinstance(spd_call, dict) else spd_call[0]
        checksum = self.make_app_checksum(app, spd['sk'], spd['adsid'])
        params = {
            "app": [app],
            "c": spd['c'],
            "checksum": checksum,
            "cpd": self.anisette.cpd,
            "o": "apptokens",
            "t": spd['GsIdmsToken'],
            "u": spd['adsid']
        }
        r = self.authenticated_request(params)
        encrypted_token = decrypt_gcm(r['et'], spd['sk'])
        if encrypted_token:
            print("Xcode token:")
            resp = plist.loads(plist.PLISTHEADER + encrypted_token)
            pp(resp)
            return (spd, XcodeSession(spd['adsid'], resp['t'][app]['token'], self.anisette))
        return (spd, r)


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

if __name__ == "__main__": main()

