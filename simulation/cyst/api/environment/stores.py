from abc import ABC, abstractmethod
from typing import List, Optional, Union

from cyst.api.environment.message import Message
from cyst.api.logic.action import Action, ActionDescription
from cyst.api.logic.exploit import Exploit, ExploitCategory
from cyst.api.network.node import Node


class ActionStore(ABC):

    @abstractmethod
    def get(self, id: str = "") -> Optional[Action]:
        pass

    @abstractmethod
    def get_ref(self, id: str = "") -> Optional[Action]:
        pass

    @abstractmethod
    def get_prefixed(self, prefix: str = "") -> List[Action]:
        pass

    @abstractmethod
    def add(self, action: ActionDescription) -> None:
        pass


class ExploitStore(ABC):

    @abstractmethod
    def get_exploit(self, id: str = "", service: str = "", category: ExploitCategory = ExploitCategory.NONE) -> Optional[List[Exploit]]:
        pass

    @abstractmethod
    def evaluate_exploit(self, exploit: Union[str, Exploit], message: Message, node: Node):
        pass
