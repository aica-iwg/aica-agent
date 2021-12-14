import heapq

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any, Union

from cyst.api.logic.action import Action, ActionParameter
from cyst.api.logic.access import Authorization, AuthenticationToken
from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Request, Response, MessageType, Message
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.network.session import Session
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service


@dataclass
class ActionQueueItemResponseMapping:
    session: Optional[str] = None
    auth: Optional[str] = None
    content: Optional[Dict[str, str]] = None


@dataclass
class ActionQueueItem:
    time: int
    target: str
    service: str
    action: Action
    parameter_references: Optional[Dict[str, Any]] = None
    session: Optional[str] = None
    auth: Optional[str] = None
    mapping: Optional[ActionQueueItemResponseMapping] = None


class ScriptedAttackerControl(ABC):
    @abstractmethod
    def execute_action(self, target: str, service: str, action: Action, session: Session = None,
                       auth: Optional[Union[Authorization, AuthenticationToken]] = None, delay: int = 0) -> None:
        pass

    @abstractmethod
    def get_last_response(self) -> Optional[Response]:
        pass

    @abstractmethod
    def enqueue_action(self, action: ActionQueueItem):
        pass


class ScriptedAttacker(ActiveService, ScriptedAttackerControl):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._env = env
        self._res = res
        self._responses = []
        self._plan = []
        self._plan_time = 0
        self._references: Dict[str, Any] = {}
        self._last_request_id = -1

    # This attacker only runs given actions. No own initiative
    def run(self):
        print("Launched a scripted attacker")
        if self._plan:
            self._execute_plan()

    def execute_action(self, target: str, service: str, action: Action, session: Session = None,
                       auth: Optional[Union[Authorization, AuthenticationToken]] = None, delay: int = 0) -> None:
        request = self._env.create_request(target, service, action, session=session, auth=auth)
        self._last_request_id = request.id
        self._env.send_message(request, delay)

    def process_message(self, message: Message) -> Tuple[bool, int]:
        print("Got response on request {} : {}".format(message.id, str(message)))
        self._responses.append(message)

        # map responses to variables
        if self._plan:
            action_item: ActionQueueItem = heapq.heappop(self._plan)[1]

            if action_item.mapping:
                mapping = action_item.mapping

                if mapping.auth:
                    self._references[mapping.auth] = message.auth

                if mapping.session:
                    self._references[mapping.session] = message.session

                if isinstance(message, Response):
                    if mapping.content:
                        pass  # TBD later

        # move on with the plan
        if self._plan:
            self._execute_plan()

        return True, 1

    def get_last_response(self) -> Optional[Response]:
        if not self._responses:
            return None
        else:
            return self._responses[-1]

    def enqueue_action(self, action: ActionQueueItem):
        heapq.heappush(self._plan, (action.time, action))

    # TODO: Currently the plan works only in a synchronous manner
    def _execute_plan(self):
        if not self._plan:
            return

        simulation_time = self._res.clock.simulation_time()
        item: ActionQueueItem = self._plan[0][1]  # item removed from heap only after processing response

        delay = item.time - simulation_time

        action = item.action
        target = self._resolve_reference(item.target)
        service = self._resolve_reference(item.service)
        session = self._resolve_reference(item.session)
        auth = self._resolve_reference(item.auth)
        if item.parameter_references:
            for i in item.parameter_references.items():
                action.parameters[i[0]] = self._resolve_reference(i[1])
            # TODO bind parameters

        self.execute_action(target, service, action, session, auth, delay)

    def _resolve_reference(self, item: str) -> Optional[Any]:
        if not item:
            return None
        if item[0] == '$':
            true_item = self._references.get(item, None)
            if not true_item:
                raise RuntimeError("Attempting to base action on unknow reference: " + item)
            return true_item
        else:
            return item

    @staticmethod
    def cast_from(o: Service) -> 'ScriptedAttacker':
        if o.active_service:
            # Had to do it step by step to shut up the validator
            service = o.active_service
            if isinstance(service, ScriptedAttacker):
                return service
            else:
                raise ValueError("Malformed underlying object passed with the Session interface")
        else:
            raise ValueError("Not an active service passed")


def create_attacker(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    attacker = ScriptedAttacker(msg, res, args)
    return attacker


service_description = ActiveServiceDescription(
    "scripted_attacker",
    "An attacker that only performs given actions. No logic whatsoever.",
    create_attacker
)