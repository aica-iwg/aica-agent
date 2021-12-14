from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union, Tuple
from uuid import uuid4

from tools.serde_customized import serialize

from cyst.api.configuration.configuration import ConfigItem
from cyst.api.configuration.logic.access import AuthorizationConfig, AccessSchemeConfig, AuthenticationProviderConfig
from cyst.api.configuration.logic.data import DataConfig
# TODO: This should be probably moved somewhere else
from cyst.api.environment.configuration import ServiceParameter

from cyst.api.logic.access import AccessLevel


@serialize
@dataclass
class ActiveServiceConfig(ConfigItem):
    type: str
    name: str
    owner: str
    access_level: AccessLevel
    configuration: Optional[Dict[str, Any]] = None
    id: str = field(default_factory=lambda: str(uuid4()))


@serialize
@dataclass
class PassiveServiceConfig(ConfigItem):
    type: str
    owner: str
    version: str
    local: bool
    access_level: AccessLevel
    authentication_providers: List[Optional[Union[AuthenticationProviderConfig, str]]] = field(default_factory=lambda: [])
    access_schemes: List[AccessSchemeConfig] = field(default_factory=lambda: [])
    public_data: List[Union[DataConfig, str]] = field(default_factory=lambda: [])
    private_data: List[Union[DataConfig, str]] = field(default_factory=lambda: [])
    public_authorizations: List[Union[AuthorizationConfig, str]] = field(default_factory=lambda: [])
    private_authorizations: List[Union[AuthorizationConfig, str]] = field(default_factory=lambda: [])
    parameters: List[Tuple[ServiceParameter, Any]] = field(default_factory=lambda: [])
    id: str = field(default_factory=lambda: str(uuid4()))
