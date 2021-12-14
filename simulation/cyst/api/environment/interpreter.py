from abc import ABC, abstractmethod
from typing import NamedTuple, Callable, List

from cyst.api.environment.messaging import EnvironmentMessaging
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.environment.configuration import EnvironmentConfiguration
from cyst.api.environment.policy import EnvironmentPolicy
from cyst.api.environment.stores import ActionStore
from cyst.api.environment.message import Request
from cyst.api.network.node import Node


class ActionInterpreter(ABC):
    @abstractmethod
    def evaluate(self, message: Request, node: Node):
        pass


class ActionInterpreterDescription(NamedTuple):
    namespace: str
    description: str
    creation_fn: Callable[[EnvironmentConfiguration, EnvironmentResources, EnvironmentPolicy, EnvironmentMessaging], ActionInterpreter]