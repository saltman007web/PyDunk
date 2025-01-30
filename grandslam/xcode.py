from enum import Enum
from pprint import pp
import plistlib as plist
from uuid import uuid4

from .anisette import Anisette
from .common import SessionProvider
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
    BASE_URL = "https://developerservices2.apple.com/services/QH65B2/"
    SERVICES_BASE_URL = "https://developerservices2.apple.com/services/v1/"

    def __init__(
        self,
        dsid: str,
        auth_token: str,
        anisette: Anisette,
    ):
        self.dsid = dsid
        self.auth_token = auth_token
        self.anisette = anisette
        self.session = self.anisette.session

        self._account = None
        self._team = None
        self._devices = []
        self._app_ids = []
        self._app_groups = []

    def __repr__(self):
        return f"XcodeSession({self.dsid!r}, {self.auth_token!r}, {self.anisette!r})"

    def send_request_with_url(self, url: str, body: dict | None = None, params: dict | None = None) -> dict:
        if body is None: body = {}
        if params is None: params = {}
        body |= {
            "clientId": "XABBG36SBA",
            "protocolVersion": "A1234",
            "requestId": str(uuid4()).upper(),
        }
        headers = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
        }
        headers |= self.anisette.headers(True)
        headers |= {
            "X-Apple-I-Identity-Id": self.dsid,
            "X-Apple-GS-Token": self.auth_token,
        }
        resp = self.session.post(
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
        self._fetch_account()

    @property
    def account(self) -> Account:
        if self._account is None: return self._fetch_account()
        return self._account

    def _fetch_account(self) -> Account:
        self._account = Account.from_api(
            self.send_request_with_url(self.BASE_URL + "viewDeveloper.action")['developer']
        )
        return self._account

    def refresh_team(self):
        self._fetch_team()

    @property
    def team(self) -> Team:
        if self._team is None: return self._fetch_team()
        return self._team

    def _fetch_team(self) -> Team:
        self._team = Team.from_api_with_account(
            self.account,
            self.send_request_with_url(self.BASE_URL + "listTeams.action")['teams'][0]
        )
        return self._team

    def refresh_devices(self):
        self._fetch_devices_for_team()

    @property
    def devices(self):
        if len(self._devices) == 0: self._devices = self._fetch_devices_for_team()
        return self._devices

    def _fetch_devices_for_team(self):
        url = self.BASE_URL + "ios/listDevices.action"
        return [Device.from_api(d)
                for d in self.send_request_with_url(url, {"teamId": self.team.identifier})['devices']]

    def refresh_app_ids(self):
        self._fetch_app_ids()

    @property
    def app_ids(self) -> list[AppID]:
        if len(self._app_ids) == 0: return self._fetch_app_ids()
        return self._app_ids

    def _fetch_app_ids(self):
        url = self.BASE_URL + "ios/listAppIds.action"
        app_ids = self.send_request_with_url(url, {
                             "teamId": self.team.identifier,
                             "urlEncodedParameters": "include=profiles",
                         })
        pp(app_ids.keys())
        self._app_ids = [AppID.from_api(d) for d in app_ids['appIds']]
        return self._app_ids

    def refresh_app_groups(self):
        self._fetch_app_groups_for_team()

    @property
    def app_groups(self) -> list[AppGroup]:
        if len(self._app_groups) == 0: return self._fetch_app_groups_for_team()
        return self._app_groups

    def _fetch_app_groups_for_team(self) -> list[AppGroup]:
        self._app_groups = [AppGroup.from_api(g) for g in self.send_request_with_url(
            self.BASE_URL + "ios/listApplicationGroups.action",
            {"teamId": self.team.identifier}
        )['applicationGroupList']]
        return self._app_groups

    def fetch_profiles_for_team(self):
        return self.send_request_with_url(
            self.BASE_URL + "ios/listProfiles.action",
            {
                "teamId": self.team.identifier,
                "include": ProfileIncludeFilter.entitlements(),
                "fields[certificates]": CertificateFieldFilter.default(),
                "fields[devices]": "name,udid,addedDate",
                "fields[bundleIds]": "name,identifier,bundleType,platform,wildcard,dateModified,dateCreated,seedId"
            }
        )

