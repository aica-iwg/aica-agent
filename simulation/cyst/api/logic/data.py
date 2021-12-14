from abc import ABC, abstractmethod
from dataclasses import dataclass

from cyst.api.utils.configuration import ConfigItem


@dataclass
class DataConfig(ConfigItem):
    owner: str
    description: str


class Data(ABC):

    @property
    @abstractmethod
    def id(self):
        pass

    @property
    @abstractmethod
    def owner(self):
        pass

    @property
    @abstractmethod
    def description(self):
        pass
