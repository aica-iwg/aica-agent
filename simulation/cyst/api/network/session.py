from abc import abstractmethod, ABC
from netaddr import IPAddress
from typing import List, Optional, Tuple


class Session(ABC):

    @property
    @abstractmethod
    def owner(self) -> str:
        pass

    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def parent(self) -> Optional['Session']:
        pass

    @property
    @abstractmethod
    def path(self) -> List[Tuple[Optional[IPAddress], Optional[IPAddress]]]:
        pass

    @property
    @abstractmethod
    def end(self) -> Optional[IPAddress]:
        pass

    @property
    @abstractmethod
    def start(self) -> Optional[IPAddress]:
        pass
