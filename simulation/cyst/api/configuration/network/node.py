from dataclasses import dataclass, field
from typing import List, Union
from uuid import uuid4
from tools.serde_customized import serialize

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.configuration.host.service import ActiveServiceConfig, PassiveServiceConfig
from cyst.api.configuration.network.elements import InterfaceConfig


@serialize
@dataclass
class NodeConfig(ConfigItem):
    active_services: List[Union[ActiveServiceConfig, str]]
    passive_services: List[Union[PassiveServiceConfig, str]]
    traffic_processors: List[Union[ActiveServiceConfig, str]]
    shell: str
    interfaces: List[Union[InterfaceConfig, str]]
    id: str = field(default_factory=lambda: str(uuid4()))
