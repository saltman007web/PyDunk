from requests import Session


class SessionProvider:
    def __init__(self, session: Session | None = None):
        self._session = session

    @property
    def session(self):
        if self._session is None: self._session = Session()
        return self._session

    @session.setter
    def session(self, new: Session):
        if not isinstance(new, Session): raise ValueError(f"{type(new)} is not of type Session!")
        self._session = new
