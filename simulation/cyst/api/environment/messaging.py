from abc import ABC, abstractmethod
from netaddr import IPAddress
from typing import Any, Optional, Union

from cyst.api.environment.message import Message, Request, Status
from cyst.api.logic.action import Action
from cyst.api.logic.access import Authorization, AuthenticationTarget, AuthenticationToken
from cyst.api.network.session import Session


class EnvironmentMessaging(ABC):

    @abstractmethod
    def send_message(self, message: Message, delay: int = 0) -> None:
        pass

    @abstractmethod
    def create_request(self, dst_ip: Union[str, IPAddress], dst_service: str = "", action: Action = None,
                       session: Session = None, auth: Optional[Union[Authorization, AuthenticationToken]] = None) -> Request:
        pass

    @abstractmethod
    def create_response(self, request: Request, status: Status, content: Optional[Any] = None, session: Optional[Session] = None,
                        auth: Optional[Union[Authorization, AuthenticationTarget]] = None):
        pass
