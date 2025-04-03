import os
from getpass import getpass

from . import XcodeSession


adsid = os.environ.get("APPLE_DSID")
if not adsid: adsid = input("Apple DSID: ")
token = os.environ.get("APPLE_XCODE_TOKEN")
if not token: token = getpass("'com.apple.gs.xcode.auth' token: ")
x = XcodeSession(adsid, token)

