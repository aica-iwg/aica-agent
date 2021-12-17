from typing import Union, Optional, Any
from netaddr import IPAddress

from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.messaging import Message, Request, Status
from cyst.api.logic.access import Authorization
from cyst.api.logic.action import Action
from cyst.api.network.session import Session

from cyst.core.environment.message import RequestImpl
from cyst.core.network.elements import Endpoint


# EnvironmentProxy is a proxy for the environment, which is passed to each active node. It takes care of routing of
# messages and prevents forging of Messages and spooky action in the distance
class EnvironmentProxy(EnvironmentMessaging):

    def __init__(self, env: EnvironmentMessaging, node_id: str, service_id: str) -> None:
        self._env = env
        # Node is resolved on the first attempt to send a message
        self._node_id = node_id
        self._service_id = service_id

    def send_message(self, message: Message, delay: int = 0) -> None:
        # Dummy origin, to make it work with Environment.send_message
        if isinstance(message, RequestImpl):
            message.set_origin(Endpoint(self._node_id, -1))
            message.src_service = self._service_id

        self._env.send_message(message, delay)

    def create_request(self, dst_ip: Union[str, IPAddress], dst_service: str = "",
                       action: Action = None, session: Session = None, auth: Authorization = None) -> Request:
        return self._env.create_request(dst_ip, dst_service, action, session, auth)

    def create_response(self, request: Request, status: Status, content: Optional[Any] = None,
                        session: Optional[Session] = None, auth: Optional[Authorization] = None):
        return self._env.create_response(request, status, content, session, auth)
