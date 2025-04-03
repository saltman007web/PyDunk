

class Account:
    def __init__(
        self,
        apple_id: str,
        identifier: int,
        first: str,
        last: str,
    ):
        self.apple_id = apple_id
        self.identifier = identifier
        self.first = first
        self.last = last

    def __repr__(self):
        return f"{self.__class__.__name__}({self.apple_id!r}, {self.identifier!r}, {self.first!r}, {self.last!r})"

    @property
    def name(self):
        return f"{self.first} {self.last}"

    @classmethod
    def from_api(cls, data: dict):
        return cls(
            data['email'],
            data['personId'],
            data['dsFirstName'] if isinstance(data['dsFirstName'], str) else data['firstName'],
            data['dsLastName'] if isinstance(data['dsLastName'], str) else data['lastName'],
        )
