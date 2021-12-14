from dataclasses import dataclass, field
from typing import List, Union, Optional
from uuid import uuid4
from tools.serde_customized import serialize
from cyst.api.configuration.configuration import ConfigItem
from cyst.api.configuration.network.elements import InterfaceConfig, RouteConfig
from cyst.api.configuration.network.firewall import FirewallConfig


@serialize
@dataclass
class RouterConfig(ConfigItem):
    interfaces: List[Union[InterfaceConfig]]
    routing_table: List[RouteConfig] = field(default_factory=list)  # TODO: check if such a default is ok
    firewall: Optional[FirewallConfig] = field(default=None)
    id: str = field(default_factory=lambda: str(uuid4()))
