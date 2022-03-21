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


class NCIAIDS(ActiveService):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._msg = env
        self._res = res
        self._defender_ip = args["defender_ip"]

    # The IDS only reacts to received events in metadata
    def run(self):
        print("Launched NCIA IDS")

    def process_message(self, message: Message) -> Tuple[bool, int]:
        if message.type == MessageType.RESPONSE:
            return False, 1

        if message.metadata and message.metadata.event:
            print("IDS detected an event: " + message.metadata.event)

            action = self._res.action_store.get("ncia:communicate")
            action.parameters["data"].value = message.metadata

            r = self._msg.create_request(self._defender_ip, "ncia_defender", action)
            self._msg.send_message(r, 1)

        # The IDS is consuming the incoming messages, as it is expected to reside behind a span port
        return False, 1


def create_ids(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    ids = NCIAIDS(msg, res, args)
    return ids


service_description = ActiveServiceDescription(
    "ncia_ids",
    "An IDS configured for the AICAProto21 demo for NCIA",
    create_ids
)