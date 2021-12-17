from dataclasses import dataclass, field
from typing import List, Union
from uuid import uuid4
from tools.serde_customized import serialize

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.configuration.network.elements import ConnectionConfig
from cyst.api.configuration.network.node import NodeConfig
from cyst.api.configuration.network.router import RouterConfig


@serialize
@dataclass
class NetworkConfig(ConfigItem):
    nodes: List[Union[NodeConfig, RouterConfig, str]]
    connections: List[Union[ConnectionConfig, str]]
    id: str = field(default_factory=lambda: str(uuid4()))
