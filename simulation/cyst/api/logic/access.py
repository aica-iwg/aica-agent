import uuid

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Optional, List, Tuple
from netaddr import IPAddress

from cyst.api.logic.data import Data


class AccessLevel(IntEnum):
    NONE = 0,
    LIMITED = 1,
    ELEVATED = 2


class AuthenticationTokenType(IntEnum):
    NONE = 0,
    PASSWORD = 1,
    BIOMETRIC = 2,
    DEVICE = 3


class AuthenticationTokenSecurity(IntEnum):
    OPEN = 0,
    SEALED = 1,
    HIDDEN = 2


class AuthenticationProviderType(IntEnum):
    LOCAL = 0,
    PROXY = 1,
    REMOTE = 2


class AuthenticationToken(ABC):

    @property
    @abstractmethod
    def type(self) -> AuthenticationTokenType:
        pass

    @property
    @abstractmethod
    def security(self) -> AuthenticationTokenSecurity:
        pass

    @property
    @abstractmethod
    def identity(self) -> str:
        pass

    @identity.setter
    @abstractmethod
    def identity(self, value: str) -> bool:
        pass

    @abstractmethod
    def copy(self) -> Optional['AuthenticationToken']:
        pass

    @property
    @abstractmethod
    def content(self) -> Optional[Data]:
        pass


class AuthenticationTarget(ABC):

    @property
    @abstractmethod
    def address(self) -> Optional[IPAddress]:
        pass

    @property
    @abstractmethod
    def service(self) -> str:
        pass

    @property
    @abstractmethod
    def tokens(self) -> List[AuthenticationTokenType]:
        pass


class Authorization(ABC):

    @property
    @abstractmethod
    def identity(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def access_level(self) -> AccessLevel:
        pass

    @property
    @abstractmethod
    def expiration(self) -> int:
        pass

    @property
    @abstractmethod
    def token(self) -> uuid.UUID:
        pass


class AuthenticationProvider(ABC):

    @property
    @abstractmethod
    def type(self) -> AuthenticationProviderType:
        pass

    @property
    @abstractmethod
    def target(self) -> AuthenticationTarget:
        pass

    @abstractmethod
    def token_is_registered(self, token: AuthenticationToken):
        pass


class AccessScheme(ABC):

    @property
    @abstractmethod
    def factors(self) -> List[Tuple[AuthenticationProvider, int]]:
        pass

    @property
    @abstractmethod
    def identities(self) -> List[str]:
        pass

    @property
    @abstractmethod
    def authorizations(self) -> List[Authorization]:
        pass
