from abc import ABC, abstractmethod
from collections import Sequence
from dataclasses import dataclass, field
from enum import Enum
from flags import Flags
from typing import NamedTuple, List, Tuple, Optional, Any, Dict, Union

from cyst.api.logic.access import AuthenticationToken
from cyst.api.logic.exploit import Exploit


class ActionParameterDomainType(Enum):
    ANY = 0,
    RANGE = 1,
    OPTIONS = 2


class ActionParameterDomain(Sequence):
    @property
    @abstractmethod
    def type(self) -> ActionParameterDomainType:
        pass

    @property
    @abstractmethod
    def range_min(self) -> int:
        pass

    @property
    @abstractmethod
    def range_max(self) -> int:
        pass

    @property
    @abstractmethod
    def range_step(self) -> int:
        pass

    @property
    @abstractmethod
    def options(self) -> List[Any]:
        pass

    @abstractmethod
    def validate(self, value: Any) -> bool:
        pass

    @property
    @abstractmethod
    def default(self) -> Any:
        pass

    @abstractmethod
    def __getitem__(self, item: int) -> Any:
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass


class ActionParameterType(Enum):
    NONE = 0,
    IDENTITY = 1,
    IDENTIFIER = 2,
    DURATION = 3,
    TOKEN = 4


@dataclass
class ActionParameter:
    type: ActionParameterType
    name: str
    domain: ActionParameterDomain
    value: Optional[Union[str, Any]] = None


class ActionToken(Flags):
    NONE = (),
    AUTH = (),
    DATA = (),
    EXPLOIT = (),
    SESSION = ()


class ActionDescription(NamedTuple):
    id: str
    description: str
    parameters: List[ActionParameter]
    tokens: List[Tuple[ActionToken, ActionToken]]


class Action(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def namespace(self) -> str:
        pass

    @property
    @abstractmethod
    def fragments(self) -> List[str]:
        pass

    @property
    @abstractmethod
    def exploit(self) -> Exploit:
        pass

    @abstractmethod
    def set_exploit(self, exploit: Optional[Exploit]):
        pass

    @property
    @abstractmethod
    def parameters(self) -> Dict[str, ActionParameter]:
        pass

    @abstractmethod
    def add_parameters(self, *params: ActionParameter):
        pass

    @property
    @abstractmethod
    def tokens(self) -> List[Tuple[ActionToken, ActionToken]]:
        pass

    @abstractmethod
    def copy(self):
        pass
