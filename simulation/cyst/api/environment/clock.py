from abc import ABC, abstractmethod
from time import struct_time
from typing import Any

from cyst.api.host.service import ActiveService


class Clock(ABC):

    @abstractmethod
    def simulation_time(self) -> int:
        pass

    @abstractmethod
    def hybrid_time(self) -> struct_time:
        pass

    @abstractmethod
    def timeout(self, service: ActiveService, delay: int, content: Any):
        pass
