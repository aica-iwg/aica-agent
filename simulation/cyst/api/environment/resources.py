from abc import ABC, abstractmethod

from cyst.api.environment.stores import ActionStore, ExploitStore
from cyst.api.environment.clock import Clock


class EnvironmentResources(ABC):

    @property
    @abstractmethod
    def action_store(self) -> ActionStore:
        pass

    @property
    @abstractmethod
    def exploit_store(self) -> ExploitStore:
        pass

    @property
    @abstractmethod
    def clock(self) -> Clock:
        pass
