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
class BlockEntry:
    source: IPAddress
    start: int
    duration: int


class EventDrivenHostIDS(ActiveService):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._msg = env
        self._res = res

        self._blocks: Dict[IPAddress, BlockEntry] = {}

    # The IDS only reacts to received events in metadata
    def run(self):
        print("Launched event-driven host IDS")

    def process_message(self, message: Message) -> Tuple[bool, int]:
        # Processed events:
        # alert:scan_detected
        # alert:unauthorized_access
        # alert:data_manipulation

        # This IDS works only on messages, which provide metadata
        if not message.metadata or not message.metadata.src_ip or not message.metadata.event:
            return True, 1

        src = message.metadata.src_ip
        evt = message.metadata.event

        if evt is None:
            duration = 0
        elif evt == "alert:scan_detected":
            duration = 30
        elif evt == "alert:unauthorized_access":
            duration = 100
        elif evt == "alert:data_manipulation":
            duration = 100
        else:
            duration = 0

        time = self._res.clock.simulation_time()

        blocked = False

        # The IP was blocked already
        if src in self._blocks:
            block = self._blocks[src]
            # The block is still active
            if time <= block.start + block.duration:
                blocked = True
                # Extend block duration
                block.duration += duration
            # The block is inactive
            else:
                # Nothing happened, remove it
                if duration == 0:
                    del self._blocks[src]
                # Create new block from now
                else:
                    blocked = True
                    self._blocks[src] = BlockEntry(src, time, duration)
        # The IP should be blocked
        elif duration > 0:
            blocked = True
            self._blocks[src] = BlockEntry(src, time, duration)

        if not blocked:
            return True, 0
        else:
            m = self._msg.create_response(message.cast_to(Request), Status(StatusOrigin.NETWORK, StatusValue.FAILURE), session=message.session)
            self._msg.send_message(m)
            return False, 1


def create_ids(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    attacker = EventDrivenHostIDS(msg, res, args)
    return attacker


service_description = ActiveServiceDescription(
    "event_driven_host_ids",
    "An IDS that performs blocking based on events in metadata",
    create_ids
)