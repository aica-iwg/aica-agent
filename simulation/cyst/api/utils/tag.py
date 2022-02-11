from abc import ABC, abstractmethod
from typing import List


class Tag(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def name_list(self) -> List[str]:
        pass

    @property
    @abstractmethod
    def value(self) -> int:
        pass
