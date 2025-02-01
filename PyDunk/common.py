from requests import Session


class SessionProvider:
    def __init__(self, session: Session | None = None):
        self.__session = session

    @property
    def _session(self) -> Session:
        if self.__session is None: self.__session = Session()
        return self.__session

    @_session.setter
    def _session(self, new: Session):
        if not isinstance(new, Session): raise ValueError(f"{type(new)} is not of type Session!")
        self.__session = new
