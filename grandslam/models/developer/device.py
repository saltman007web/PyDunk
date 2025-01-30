from enum import Enum



class DeviceKind(Enum):
    UNKNOWN = 0
    IPHONE  = 1
    IPAD    = 2
    TVOS    = 3
    WATCH   = 4

    @classmethod
    def from_str(cls, s: str):
        if s == "iphone": return cls.IPHONE
        elif s == "ipad": return cls.IPAD
        elif s == "tvOS": return cls.TVOS
        elif s == "watch": return cls.WATCH
        return cls.UNKNOWN

class Device:
    def __init__(
        self,
        device_id: str,
        name: str,
        udid: str,
        kind: DeviceKind,
    ):
        self.device_id = device_id
        self.name = name
        self.udid = udid
        self.kind = kind

    def __repr__(self):
        return f"{self.__class__.__name__}({self.name!r}, {self.udid!r}, {self.kind!r})"

    @classmethod
    def from_api(cls, data: dict):
        return cls(
            data['deviceId'],
            data['name'],
            data['deviceNumber'],
            DeviceKind.from_str(data['deviceClass'])
        )
