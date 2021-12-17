from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any
from netaddr import IPAddress

from cyst.api.logic.action import Action
from cyst.api.logic.access import Authorization, AccessLevel
from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Request, Response, MessageType, Message, Status, StatusValue, StatusOrigin
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.network.session import Session
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service


@dataclass
class Redirect:
    id: int
    src_ip: IPAddress
    dst_ip: IPAddress


class NCIARedirector(ActiveService):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._msg = env
        self._res = res
        self._redirects = {}
        self._cache = {}

    # The IDS only reacts to received events in metadata
    def run(self):
        print("Launched NCIA Redirector")

    def process_message(self, message: Message) -> Tuple[bool, int]:
        if message.type == MessageType.REQUEST:
            action = message.cast_to(Request).action
            if action.id == "ncia:redirect":
                src_ip = action.parameters["src_ip"].value
                dst_ip = action.parameters["dst_ip"].value

                self._redirects[src_ip] = dst_ip
            else:
                if str(message.src_ip) in self._redirects:
                    r = Redirect(message.id, message.src_ip, message.dst_ip)
                    self._cache[message.id] = r

                    message._dst_ip = IPAddress(self._redirects[str(message.src_ip)])

        # Rewrite dst_ip and src_ip

        if message.type == MessageType.RESPONSE:
            if message.id in self._cache:
                message._src_ip = self._cache[message.id].dst_ip

        return True, 1


def create_redirector(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    redirector = NCIARedirector(msg, res, args)
    return redirector


service_description = ActiveServiceDescription(
    "ncia_redirector",
    "A service that takes care of correct redirection",
    create_redirector
)