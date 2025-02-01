import json
from enum import Enum
from pprint import pp
import plistlib as plist
from uuid import uuid4

from .auth import Anisette
from .common import SessionProvider
from .models import GSAuthToken, GSAuthTokens
from .models.developer import Account, AppID, AppGroup, Device, Team


class ProfileIncludeKind(Enum):
    """
    (
        'appConsentBundleId',
        'appGroups',
        'bundleId',
        'capability',
        'certificates',
        'cloudContainers',
        'identityMerchantIds',
        'macBundleId',
        'merchantIds',
        'parentBundleId',
        'relatedAppConsentBundleIds'
    )
    """
    BUNDLE = "bundleId"
    CERTIFICATES = "certificates"
    DEVICES = "devices"
    BUNDLE_CAPABILITIES = BUNDLE + "bundleIdCapabilities"
    BUNDLE_MACAPPID = BUNDLE_CAPABILITIES + "macBundleId"
    BUNDLE_APPGROUPS = BUNDLE_CAPABILITIES + "appGroups"
    BUNDLE_CLOUDCONTAINERS = BUNDLE_CAPABILITIES + "cloudContainers"
    BUNDLE_CAPABILITY = BUNDLE_CAPABILITIES + "capability"
    BUNDLE_MERCHANTID = BUNDLE_CAPABILITIES + "merchantIds"
    BUNDLE_IDENTITYMERCHANTID = BUNDLE_CAPABILITIES + "identityMerchantIds"

class ProfileIncludeFilter:
    K = ProfileIncludeKind
    _D = [K.BUNDLE, K.CERTIFICATES, K.DEVICES]
    _DC = [K.BUNDLE, K.CERTIFICATES, K.DEVICES, K.BUNDLE_CAPABILITIES, K.BUNDLE_MACAPPID, K.BUNDLE_APPGROUPS, K.BUNDLE_CLOUDCONTAINERS]

    def __init__(self, params: list[K]):
        self.params = params

    def __str__(self):
        return ",".join(p.value for p in self.params)

    @classmethod
    def default(cls) -> str:
        return str(cls(cls._D))

    @classmethod
    def entitlements(cls) -> str:
        return str(cls(cls._D))


class CertificateFieldKind(Enum):
    TYPE_ID = "certificateTypeId"
    TYPE_NAME = "certificateTypeName"
    SERIAL_NUMBER = "serialNumber"
    MACHINE_ID = "machineId"
    MACHINE_NAME = "machineName"
    REQUESTED = "requestedDate"
    EXPIRATION = "expirationDate"
    STATUS = "status"
    CONTENT = "certificateContent"


class CertificateFieldFilter:
    K = CertificateFieldKind
    _D = [K.TYPE_ID, K.TYPE_NAME, K.SERIAL_NUMBER, K.MACHINE_ID, K.MACHINE_NAME, K.REQUESTED, K.EXPIRATION, K.STATUS, K.CONTENT]

    def __init__(self, params: list[K]):
        self.params = params

    def __str__(self):
        return ",".join(p.value for p in self.params)

    @classmethod
    def default(cls) -> str:
        return str(cls(cls._D))


class XcodeSession(SessionProvider):
    _BASE_URL = "https://developerservices2.apple.com/services/QH65B2/"
    _SERVICES_BASE_URL = "https://developerservices2.apple.com/services/v1/"

    def __init__(
        self,
        dsid: str,
        auth_token: str | GSAuthToken,
        anisette: Anisette = Anisette(),
    ):
        self.dsid = dsid
        self.auth_token = auth_token.token if isinstance(auth_token, GSAuthToken) else auth_token
        self._anisette = anisette
        self._session = self._anisette._session
        self._session.verify = False

        self._account = None
        self._team = None
        self._devices = []
        self._app_ids = []
        self._app_groups = []

    def __repr__(self):
        return f"XcodeSession({self.dsid!r}, {self.auth_token!r}, {self._anisette!r})"

    @property
    def _base_headers(self) -> dict:
        headers = {
            "User-Agent": "Xcode",
            "Accept-Language": "en-us",
            "X-Apple-I-Identity-Id": self.dsid,
            "X-Apple-GS-Token": self.auth_token,
        }
        return headers | self._anisette.headers(True)

    @property
    def _base_body(self) -> dict:
        if self._team is not None:
            return {"teamId": self.team.identifier}
        return {}

    def _json_request_with_url(self, url: str, body: dict | None = None) -> dict:
        headers = self._base_headers | {
            "Accept": "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json",
            "X-HTTP-Method-Override": "GET",
        }
        if body:
            return self._session.post(url, data=json.dumps(body).replace(" ", ""), headers=headers).json()
        return self._session.post(url, headers=headers).json()

    def _plist_request_with_url(self, url: str, body: dict | None = None, params: dict | None = None) -> dict:
        body = self._base_body if body is None else body | self._base_body
        if params is None: params = {}
        body |= {
            "clientId": "XABBG36SBA",
            "protocolVersion": "A1234",
            "requestId": str(uuid4()).upper(),
        }
        headers = self._base_headers | {
            "Accept": "text/x-xml-plist",
            "Content-Type": "text/x-xml-plist",
        }
        resp = self._session.post(
            url,
            headers=headers,
            params=params,
            data=plist.dumps(body)
        ).content
        try:
            return plist.loads(resp)
        except plist.InvalidFileException:
            return resp

    def refresh_account(self):
        return self._fetch_account()

    @property
    def account(self) -> Account:
        if self._account is None: return self.refresh_account()
        return self._account

    def _fetch_account(self) -> Account:
        self._account = Account.from_api(
            self._plist_request_with_url(self._BASE_URL + "viewDeveloper.action")['developer']
        )
        return self._account

    def refresh_team(self):
        return self._fetch_team()

    @property
    def team(self) -> Team:
        if self._team is None: return self.refresh_team()
        return self._team

    def _fetch_team(self) -> Team:
        self._team = Team.from_api_with_account(
            self.account,
            self._plist_request_with_url(self._BASE_URL + "listTeams.action")['teams'][0]
        )
        return self._team

    def refresh_devices(self):
        return self._fetch_devices_for_team()

    @property
    def devices(self):
        if len(self._devices) == 0: self._devices = self.refresh_devices()
        return self._devices

    def _fetch_devices_for_team(self):
        url = self._BASE_URL + "ios/listDevices.action"
        return [Device.from_api(d) for d in self._plist_request_with_url(url)['devices']]

    def refresh_app_ids(self):
        return self._fetch_app_ids()

    @property
    def app_ids(self) -> list[AppID]:
        if len(self._app_ids) == 0: return self.refresh_app_ids()
        return self._app_ids

    def _fetch_app_ids(self):
        url = self._BASE_URL + "ios/listAppIds.action"
        app_ids = self._plist_request_with_url(url, {"teamId": self.team.identifier})
        self._app_ids = [AppID.from_api(d) for d in app_ids['appIds']]
        return self._app_ids

    def refresh_app_groups(self):
        return self._fetch_app_groups_for_team()

    @property
    def app_groups(self) -> list[AppGroup]:
        if len(self._app_groups) == 0: return self.refresh_app_groups()
        return self._app_groups

    def _fetch_app_groups_for_team(self) -> list[AppGroup]:
        self._app_groups = [AppGroup.from_api(g) for g in self._plist_request_with_url(self._BASE_URL + "ios/listApplicationGroups.action")['applicationGroupList']]
        return self._app_groups

    def fetch_all_for_team(self):
        return self._json_request_with_url(
            self._SERVICES_BASE_URL + "profiles",
            {
                "urlEncodedQueryParams": f"teamId={self.team.identifier}&include=bundleId,certificates,devices&limit=200"
            }
        )

if __name__ == '__main__':
    import os
    from getpass import getpass
    adsid = os.environ.get("APPLE_DSID")
    if not adsid: adsid = input("Apple DSID: ")
    token = os.environ.get("APPLE_XCODE_TOKEN")
    if not token: token = getpass("'com.apple.gs.xcode.auth' token: ")
    x = XcodeSession(adsid, token)

