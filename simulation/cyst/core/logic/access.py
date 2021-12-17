
import uuid

from typing import List, Tuple, Optional
from netaddr import IPAddress

from cyst.api.configuration.logic.access import AccessLevel
from cyst.api.logic.access import Authorization, AuthenticationToken, AuthenticationTokenSecurity, \
    AuthenticationTokenType, AuthenticationProvider, AuthenticationTarget, AuthenticationProviderType, AccessScheme
from cyst.api.logic.data import Data
from cyst.core.logic.data import DataImpl


class AuthorizationImpl(Authorization):
    def __init__(self, identity: str = "", nodes: List[str] = None, services: List[str] = None,
                 access_level: AccessLevel = AccessLevel.NONE, id: Optional[str] = None, token: Optional[str] = None):
        if services is None or not services:
            services = ["*"]
        if nodes is None or not nodes:
            nodes = ["*"]
        self._id = id
        self._identity = identity
        self._nodes = nodes
        self._services = services
        self._access_level = access_level
        self._token = token
        self._expiration = -1  # TODO

    def __eq__(self, other: 'Authorization') -> bool:
        if not other:
            return False

        other = AuthorizationImpl.cast_from(other)
        return self.id == other.id or (
                self.identity == other.identity and
                self.nodes == other.nodes and
                self.services == other.services and
                self.access_level == other.access_level and
                self.token == other.token
        )

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, value: str) -> None:
        self._id = value

    @property
    def identity(self) -> str:
        return self._identity

    @identity.setter
    def identity(self, value: str) -> None:
        self._identity = value

    @property
    def nodes(self) -> List[str]:
        return self._nodes

    @nodes.setter
    def nodes(self, value: List[str]) -> None:
        self._nodes = value

    @property
    def services(self) -> List[str]:
        return self._services

    @services.setter
    def services(self, value: List[str]) -> None:
        self._services = value

    @property
    def access_level(self) -> AccessLevel:
        return self._access_level

    @access_level.setter
    def access_level(self, value: AccessLevel) -> None:
        self._access_level = value

    @property
    def token(self) -> Optional[uuid.UUID]:
        return self._token

    @token.setter
    def token(self, value: uuid) -> None:
        self._token = value

    def matching_id(self, other: Authorization):
        return self.id == AuthorizationImpl.cast_from(other).id

    def __str__(self) -> str:
        return "[Id: {}, Identity: {}, Nodes: {}, Services: {}, Access Level: {}, Token: {}]".format(self.id,
                                                                                                     self.identity,
                                                                                                     self.nodes,
                                                                                                     self.services,
                                                                                                     self.access_level.name,
                                                                                                     self.token)

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def cast_from(o: Authorization) -> 'AuthorizationImpl':
        if isinstance(o, AuthorizationImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Authorization interface")

    @property
    def expiration(self) -> int:
        return self._expiration


class PolicyStats:
    def __init__(self, authorization_entry_count: int = 0):
        self._authorization_entry_count = authorization_entry_count

    @property
    def authorization_entry_count(self):
        return self._authorization_entry_count


# ----------------------------------------------------------------------------------------------------------------------
# New version
# ----------------------------------------------------------------------------------------------------------------------

class AuthenticationTokenImpl(AuthenticationToken):

    def __init__(self, token_type: AuthenticationTokenType, security: AuthenticationTokenSecurity, identity: str,
                 is_local: bool):
        self._type = token_type
        self._security = security
        self._identity = identity
        self._is_local = is_local

        # create data according to the security
        # TODO: Until the concept of sealed data is introduced in the code, all is assumed to be OPEN
        value = uuid.uuid4()
        self._content = None

    @property
    def type(self) -> AuthenticationTokenType:
        return self._type

    @property
    def is_local(self):
        return self._is_local

    @property
    def security(self) -> AuthenticationTokenSecurity:
        return self._security

    @property
    def identity(self) -> str:
        return self._identity

    def copy(self) -> Optional[AuthenticationToken]:
        pass # TODO different uuid needed????

    @property
    def content(self) -> Optional[Data]:
        return self._content

    @staticmethod
    def is_local_instance(obj: AuthenticationToken):
        if isinstance(obj, AuthenticationTokenImpl):
            return obj.is_local
        return False

    def _set_content(self, value) -> 'AuthenticationToken':
        # this is only needed until we resolve hashed/encrypted data
        self._content = DataImpl("", value)
        return self  # just so we can chain call with constructor



class AuthenticationTargetImpl(AuthenticationTarget):
    def __init__(self, tokens: List[AuthenticationTokenType], service: Optional[str] = None,
                 ip: Optional[IPAddress] = None):
        self._address = ip
        self._service = service
        self._tokens = tokens

    @property
    def address(self) -> Optional[IPAddress]:
        return self._address

    @property
    def service(self) -> str:
        return self._service

    @property
    def tokens(self) -> List[AuthenticationTokenType]:
        return self._tokens

    @address.setter
    def address(self, ip: IPAddress):
        self._address = ip

    @service.setter
    def service(self, serv: str):
        self._service = serv


class AccessSchemeImpl(AccessScheme):
    def __init__(self):
        self._providers = []
        self._authorizations = []
        self._identities = []

    def add_provider(self, provider: AuthenticationProvider):
        self._providers.append((provider, len(self._providers)))

    def add_identity(self, identity: str):
        self._identities.append(identity)

    def add_authorization(self, auth: Authorization):
        self._authorizations.append(auth)

    @property
    def factors(self) -> List[Tuple[AuthenticationProvider, int]]:
        return self._providers
    # TODO : what is the number?? I will just use order ATM

    @property
    def identities(self) -> List[str]:
        return self._identities

    @property
    def authorizations(self) -> List[Authorization]:
        return self._authorizations

    @staticmethod
    def cast_from(other: AccessScheme):
        if isinstance(other, AccessSchemeImpl):
            return other
        else:
            raise ValueError("Malformed underlying object passed with the AccessScheme interface")


class AuthenticationProviderImpl(AuthenticationProvider):

    def __init__(self, provider_type: AuthenticationProviderType, token_type: AuthenticationTokenType,
                 security: AuthenticationTokenSecurity, ip: Optional[IPAddress], timeout: int):

        self._provider_type = provider_type
        self._token_type = token_type
        self._security = security
        self._timeout = timeout

        self._tokens = set()
        self._target = self._create_target()

        if provider_type != AuthenticationProviderType.LOCAL and ip is None:
            raise RuntimeError("Non-local provider needs ip address")
        self._set_address(ip)

    @property
    def type(self) -> AuthenticationProviderType:
        return self._provider_type

    @property
    def target(self) -> AuthenticationTarget:
        return self._target

    @property
    def token_type(self):
        return self._token_type

    @property
    def security(self):
        return self._security

    def token_is_registered(self, token: AuthenticationToken):
        for t in self._tokens:
            if t.identity == token.identity and token.content is not None:
                # This is pretty weak but until encrypted/hashed stuff is implemented its okay for testing
                return True
        return False

    def add_token(self, token: AuthenticationToken):
        self._tokens.add(token)

    def _create_target(self):
        # TODO: inherit from provider? or should we do something else?
        return AuthenticationTargetImpl([self._token_type])

    def set_service(self, srv_id: str):

        if self._target.service is None:
            self._target.service = srv_id
        else:
            raise RuntimeError  # TODO check what should be done here, exception might be too harsh

    def _set_address(self, ip: IPAddress):
        if self._target.address is None:
            self._target.address = ip
        else:
            raise RuntimeError
