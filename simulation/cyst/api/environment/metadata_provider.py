from abc import ABC, abstractmethod
from typing import Callable, NamedTuple

from cyst.api.environment.configuration import ActionConfiguration
from cyst.api.environment.stores import ActionStore
from cyst.api.logic.action import Action
from cyst.api.logic.metadata import Metadata


class MetadataProvider(ABC):
    @abstractmethod
    def register_action_parameters(self) -> None:
        pass

    @abstractmethod
    def get_metadata(self, action: Action) -> Metadata:
        pass


class MetadataProviderDescription(NamedTuple):
    namespace: str
    description: str
    creation_fn: Callable[[ActionStore, ActionConfiguration], MetadataProvider]
