from abc import ABC, abstractmethod
from enum import Enum, auto
from netaddr import IPAddress
from typing import Any, Optional, Union, NamedTuple, TypeVar, Type

from cyst.api.network.session import Session
from cyst.api.logic.access import Authorization, AuthenticationToken, AuthenticationTarget
from cyst.api.logic.action import Action
from cyst.api.logic.metadata import Metadata


class MessageType(Enum):
    TIMEOUT = 0
    REQUEST = 1
    RESPONSE = 2


class StatusOrigin(Enum):
    NETWORK = 0
    NODE = 1
    SERVICE = 2
    SYSTEM = 99


class StatusValue(Enum):
    SUCCESS = 0
    FAILURE = 1
    ERROR = 2


# Status detail provides another introspection mechanism to active services into the nature of failures and errors
# Status detail follows unified naming convention WHAT_WHY, where WHY is one of the following:
# - NOT_PROVIDED: WHAT was not passed as a parameter, even though it is required
# - NOT_EXISTING: WHAT does not exist within the context of current simulation run (e.g., service name, user name, etc.)
# - NOT_APPLICABLE: WHAT cannot be used (e.g., wrong authorization, wrong exploit parameters, etc.)
# - NOT_SUPPORTED: WHAT exists as a valid concept, but the target does not support it (e.g., attempting to open a session to a service that does not support it)
# - NEXT: WHAT was a correct step towards success, but another WHAT is required
class StatusDetail(Enum):
    UNKNOWN = 0
    # NODE.FAILURE
    PRIVILEGES_NOT_APPLICABLE = auto()

    # NODE.ERROR
    SERVICE_NOT_PROVIDED = auto()
    SERVICE_NOT_EXISTING = auto()
    SESSION_NOT_PROVIDED = auto()
    SESSION_NOT_APPLICABLE = auto()

    # SERVICE.FAILURE
    SESSION_CREATION_NOT_SUPPORTED = auto()
    EXPLOIT_NOT_PROVIDED = auto()
    EXPLOIT_NOT_APPLICABLE = auto()
    EXPLOIT_CATEGORY_NOT_APPLICABLE = auto()
    EXPLOIT_LOCALITY_NOT_APPLICABLE = auto()
    EXPLOIT_PARAMETER_NOT_PROVIDED = auto()
    EXPLOIT_PARAMETER_NOT_APPLICABLE = auto()
    AUTHORIZATION_NOT_PROVIDED = auto()
    AUTHORIZATION_NOT_APPLICABLE = auto()
    AUTHENTICATION_NOT_PROVIDED = auto()
    AUTHENTICATION_NOT_APPLICABLE = auto()
    AUTHENTICATION_NEXT = auto()

    # SERVICE.ERROR

    # SYSTEM.FAILURE

    # SYSTEM.ERROR
    ACTION_NOT_EXISTING = auto()


class Status(NamedTuple):
    origin: StatusOrigin
    value: StatusValue
    detail: StatusDetail = StatusDetail.UNKNOWN

    def __str__(self) -> str:
        if self.detail != StatusDetail.UNKNOWN:
            result = "({}, {}, {})".format(self.origin.name, self.value.name, self.detail.name)
        else:
            result = "({}, {})".format(self.origin.name, self.value.name, self.detail.name)
        return result


T = TypeVar('T', bound=Union['Request', 'Response', 'Timeout'])


class Message(ABC):

    @property
    @abstractmethod
    def id(self) -> int:
        pass

    @property
    @abstractmethod
    def type(self) -> MessageType:
        pass

    @property
    @abstractmethod
    def src_ip(self) -> Optional[IPAddress]:
        pass

    @property
    @abstractmethod
    def dst_ip(self) -> Optional[IPAddress]:
        pass

    @property
    @abstractmethod
    def src_service(self):
        pass

    @property
    @abstractmethod
    def dst_service(self):
        pass

    @property
    @abstractmethod
    def session(self) -> Session:
        pass

    @property
    @abstractmethod
    def auth(self) -> Optional[Union[Authorization, AuthenticationToken, AuthenticationTarget]]:
        pass

    @property
    @abstractmethod
    def ttl(self):
        pass

    @property
    @abstractmethod
    def metadata(self) -> Metadata:
        pass

    @abstractmethod
    def set_metadata(self, metadata: Metadata) -> None:
        pass

    @abstractmethod
    def cast_to(self, type: Type[T]) -> T:
        pass


class Request(Message, ABC):

    @property
    @abstractmethod
    def action(self) -> Action:
        pass


class Response(Message, ABC):

    @property
    @abstractmethod
    def status(self):
        pass

    @property
    @abstractmethod
    def content(self):
        pass


class Timeout(Message, ABC):

    @property
    @abstractmethod
    def start_time(self) -> int:
        pass

    @property
    @abstractmethod
    def duration(self) -> int:
        pass

    @property
    @abstractmethod
    def parameter(self) -> Any:
        pass
