from typing import Optional

from cyst.api.logic.action import ActionParameter, ActionParameterType
from cyst.api.environment.message import Request
from cyst.api.environment.environment import EnvironmentMessaging, EnvironmentResources
from cyst.services.ucb_attacker.target_selector import TargetSelector


class RequestCreator:
    
    def __init__(self, messaging: EnvironmentMessaging, resources: EnvironmentResources):
        self._messaging = messaging
        self._resources = resources
        _action_list = resources.action_store.get_prefixed("aif")
        self._actions = {}
        for action in _action_list:
            self._actions[action.id] = action

    def set_rit_and_submodule(self, rit: str, submodule) -> None:
        # submodule type is AttackerSubodule, but once again, there is cyclic dependency
        self._rit = rit
        self._submodule = submodule

    def ready(self) -> bool:
        return True

    def request(self, targeter: TargetSelector = None) -> Request:
        return None


class HostRequester(RequestCreator):

    def request(self, targeter: TargetSelector = None) -> Request:
        action = self._actions[self._rit.split("-")[0]]
        request = self._messaging.create_request(str(targeter.host()), "", action=action, session=targeter.session(), auth=None)
        return request


class ServiceRequester(RequestCreator):

    def request(self, targeter: TargetSelector = None) -> Request:
        action = self._actions[self._rit.split("-")[0]]
        request = self._messaging.create_request(str(targeter.host()), targeter.service(), action=action, session=targeter.session(), auth=None)
        return request


class ServiceAuthRequester(RequestCreator):

    def request(self, targeter: TargetSelector = None) -> Request:
        action = self._actions[self._rit.split("-")[0]]
        request = self._messaging.create_request(str(targeter.host()), targeter.service(), action=action, session=targeter.session(), auth=targeter.auth())
        return request


class ServiceExploitRequester(RequestCreator):

    def request(self, targeter: TargetSelector = None) -> Request:
        action = self._actions[self._rit.split("-")[0]]
        action.set_exploit(self._resources.exploit_store.get_exploit(targeter.exploit())[0])
        request = self._messaging.create_request(str(targeter.host()), targeter.service(), action=action, session=targeter.session(), auth=None)
        return request


class ServiceExploitAuthRequester(RequestCreator):

    def request(self, targeter: TargetSelector = None) -> Request:
        action = self._actions[self._rit.split("-")[0]]
        action.set_exploit(self._resources.exploit_store.get_exploit(targeter.exploit())[0])
        request = self._messaging.create_request(str(targeter.host()), targeter.service(), action=action, session=targeter.session(), auth=targeter.auth())
        return request


class LateralMovementRequester(RequestCreator):

    def request(self, targeter: TargetSelector = None) -> Request:
        action = self._actions[self._rit.split("-")[0]]
        attacker_class = "ucb_attacker"
        # attacker_class += targeter.class_suffix()
        action.add_parameters(ActionParameter(ActionParameterType.ID, attacker_class))
        request = self._messaging.create_request(str(targeter.host()), "", action, session=targeter.session(), auth=targeter.auth())
        return request
