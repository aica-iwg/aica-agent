from abc import ABC, abstractmethod
from typing import Tuple, Optional, Dict, Any, List
from queue import SimpleQueue
from netaddr import IPNetwork

from cyst.api.environment.message import Message
from cyst.api.utils.logger import *  # pylint: disable=unused-wildcard-import
from cyst.api.logic.access import AccessLevel
from cyst.api.host.service import ActiveService, ActiveServiceDescription
from cyst.api.network.session import Session

from cyst.services.ucb_attacker.target_selector import *  # pylint: disable=unused-wildcard-import
from cyst.services.ucb_attacker.request_creator import *  # pylint: disable=unused-wildcard-import
from cyst.services.ucb_attacker.message_processor import *  # pylint: disable=unused-wildcard-import
from cyst.services.ucb_attacker.ucb_targeter import *  # pylint: disable=unused-wildcard-import
from cyst.services.ucb_attacker.history import *  # pylint: disable=unused-wildcard-import
from cyst.services.ucb_attacker.asset_evaluator import *  # pylint: disable=unused-wildcard-import

interesting = []
# interesting = ["10.0.1.2", "10.0.1.3"]


class AttackerSubmodule:
    def __init__(self, rit: str, targeter: TargetSelector, requester: RequestCreator, processor: MessageProcessor,
                 attacker: 'ModularAttacker', bias: float = 0, interface_id: int = 0):
        self.rit = rit
        self._targeter = targeter
        self._requester = requester
        self._reward = 0
        self._attempts = 0
        self._attacker = attacker
        self._processor = processor
        self.asset_value = -1
        self.bias = bias
        self._targeter.set_rit_and_submodule(self.rit, self)
        self._requester.set_rit_and_submodule(self.rit, self)
        self._processor.set_rit_and_submodule(self.rit, self)
        attacker.add_submodule(self)

    def ready(self) -> bool:
        return self._targeter.ready() and self._requester.ready()

    def act(self) -> None:
        if isinstance(self._targeter, UCBSelector):
            self._targeter.scanner()
        self._attacker.queue_request(self._requester.request(self._targeter), self)
        self.asset_value = -1
    
    def calculate_asset_value(self):
        self.asset_value = AssetEvaluator.evaluate(self.action(), self._attacker._memory, self._attacker._exploit_store)

    def process(self, message: Response, action: AttackerAction = None):
        self._processor.process(message, action)
    
    def action(self, result: List[Any] = []) -> AttackerAction:
        return AttackerAction(result, self.rit,
                              self._targeter.host(),
                              self._targeter.service(),
                              self._targeter.session(),
                              self._targeter.auth(),
                              self._targeter.exploit())


class ModularAttackerControl(ABC):
    @abstractmethod
    def run(self) -> None:
        pass

    @abstractmethod
    def reset(self) -> None:
        pass

    @abstractmethod
    def new_host(self, ip: IPAddress) -> None:
        pass

    @abstractmethod
    def new_session(self, ip: IPAddress, session: Session) -> None:
        pass

    @abstractmethod
    def add_router_manually(self, submodule_id: int, network: IPNetwork) -> None:
        pass

    @abstractmethod
    def all_data(self) -> List[Tuple[IPAddress, Any]]:
        pass

    # TODO: Add type hints
    @abstractmethod
    def action_stats(self):
        pass


class ModularAttacker(ActiveService, ModularAttackerControl):

    ucb_logger = Log.get_logger("ucb")
    msg_logger = Log.get_logger("msg")

    def __init__(self, msg: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        # init_string pass
        # super(ModularAttacker, self).__init__(id, msg, res)
        self._messaging = msg
        self._resources = res
        self._exploit_store = res.exploit_store
        self._responses = []
        self._submodules = UCBList()
        self._memory = AttackerMemory(self)
        self._queue = SimpleQueue()
        self._request_owner = {}
        self._counter = 0
        self._actions = 0
        self.target_services = [""]
        self._target_network = IPNetwork("0.0.0.0/0")
        self._scanner_submodule = None
        self._history = History()

        # TODO passing of options is now supported. Consider abandoning the init string and use args instead
        if args and "init_string" in args and isinstance(args["init_string"], str):
            self._settings = args["init_string"].strip().split(" ")
        else:
            self._settings = []
        if "elevated" in self._settings:
            self._service_access_level = AccessLevel.ELEVATED
        else:
            self._service_access_level = AccessLevel.LIMITED
        self.add_submodules()

        self._action_mapping = {}
        self._action_attempts = []
        self._action_counter = 0
        self._last_action = None

    def reset(self):
        self._responses = []
        self._submodules = UCBList()
        self._memory = AttackerMemory(self)
        self._queue = SimpleQueue()
        self._request_owner = {}
        self._counter = 0
        self._actions = 0
        self.target_services = [""]
        self._scanner_submodule = None
        self.add_submodules()

        self._action_mapping = {}
        self._action_attempts = []
        self._action_counter = 0
        self._last_action = None

    @classmethod
    def set_target_network(cls, net: IPNetwork) -> None:
        cls._target_network = net
    
    def set_target_services(self, services: List[str]) -> None:
        self.target_services = services

    def add_submodules(self) -> None:
        ucbs = UCBSelector(self, self._target_network)
        if "no_host_scan" not in self._settings:
            rit = "aif:active_recon:host_discovery"
            AttackerSubmodule(rit, ucbs,
                              HostRequester(self._messaging, self._resources),
                              UCBSelectorProcessor(ucbs, self._memory),
                              self, -0.15)

        rit = "aif:active_recon:service_discovery"
        AttackerSubmodule(rit, HostSelector(self._memory),
                          HostRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)
        """
        rit = "aif:active_recon:information_discovery"
        AttackerSubmodule(rit, ServiceSelector(self._memory),
                          ServiceRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)
        """

        rit = "aif:active_recon:information_discovery"
        AttackerSubmodule(rit, ServiceExploitSelector(self._memory),
                          ServiceExploitRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)

        """
        rit = "aif:destroy:data_destruction"
        AttackerSubmodule(rit, ServiceAuthSelector(self._memory),
                          ServiceAuthRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)
        """

        rit = "aif:disclosure:data_exfiltration"
        AttackerSubmodule(rit, ServiceAuthSelector(self._memory),
                          ServiceAuthRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)

        rit = "aif:targeted_exploits:exploit_remote_services"
        AttackerSubmodule(rit, ServiceExploitSelector(self._memory),
                          ServiceExploitRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)

        rit = "aif:privilege_escalation:root_privilege_escalation"
        AttackerSubmodule(rit, ServiceExploitAuthSelector(self._memory),
                          ServiceExploitAuthRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)

        rit = "aif:ensure_access:command_and_control-e"
        AttackerSubmodule(rit, ServiceExploitSelector(self._memory),
                          ServiceExploitRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0.15)

        rit = "aif:ensure_access:command_and_control-a"
        AttackerSubmodule(rit, ServiceAuthSelector(self._memory),
                          ServiceAuthRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0.15)

        rit = "aif:active_recon:vulnerability_discovery"
        AttackerSubmodule(rit, ServiceSelector(self._memory),
                          ServiceRequester(self._messaging, self._resources),
                          MessageProcessor(self._memory),
                          self, 0)

        if "lateral" in self._settings:
            rit = "aif:ensure_access:lateral_movement"
            AttackerSubmodule(rit, LateralMovementSelector(self._memory),
                              LateralMovementRequester(self._messaging, self._resources),
                              MessageProcessor(self._memory),
                              self, 0)

    def add_submodule(self, submodule: AttackerSubmodule) -> int:
        self._memory.actions.add_item(submodule._targeter._rit)
        self._submodules.add_action(submodule, submodule.bias)
        if "host_discovery" in submodule.rit:
            self._scanner_submodule = self._submodules.list[-1]

    def queue_request(self, req: Request, owner: int) -> None:
        self._queue.put(req)
        self._request_owner[req.id] = owner

    def process_message(self, message: Response) -> Tuple[bool, int]:
        self._responses.append(message)
        if isinstance(message, Request):
            return True, 0

        owner = self._request_owner[message.id]

        if "host_disc" not in owner.rit:
            action = owner.action()
            if not self._memory.action_executed(action, None if message.status.value == StatusValue.SUCCESS else message.content):
                print("!")
        
        new_stuff = []
        if isinstance(message.content, list) and "service_discovery" in owner.rit:
            new_stuff.extend("svc:" + x for x in message.content)
        elif isinstance(message.content, list):
            new_stuff.extend(message.content)
        if "control" in owner.rit or "escalation" in owner.rit:
            new_stuff.append(message.authorization)
        if "control" in owner.rit:
            new_stuff.append(message.session)

        complete_action = owner.action(new_stuff)
        self.msg_logger(complete_action)
        self._history.add(complete_action)

        found_new_info = False
        
        if message.status.value == StatusValue.SUCCESS or \
           isinstance(owner._processor, UCBSelectorProcessor):
            found_new_info = owner.process(message, owner.action())
        else:
            self.process_error_message(message, owner.action())
        self.add_reward(message, found_new_info)
        return True, 1

    def add_past_rewards(self, item: Any, reward: float) -> None:
        # adds reward to stuff that was used to obtain the item
        action = self._history.source_of(item)
        self._memory.actions.add_reward(action.rit, reward, True)
        if action.ip in self._memory.hosts.keys():
            self._memory.hosts_ucb.add_reward(action.ip, reward, True)
            host = self._memory.hosts[IPAddress(action.ip)]
            if action.auth:
                self._memory.auths.add_reward(action.auth, reward, True)
            if action.service:
                host.services_ucb.add_reward(action.service, reward, True)
        self._submodules.recalc(False)

    def add_reward(self, message: Response, found_new_info: bool) -> None:
        rit = self._request_owner[message.id]._targeter._rit

        reward = 1 if found_new_info else 0
        self._memory.actions.add_reward(rit, reward)
        if IPAddress(message.src_ip) in self._memory.hosts.keys():
            self._memory.hosts_ucb.add_reward(IPAddress(message.src_ip), reward)
            host = self._memory.hosts[IPAddress(message.src_ip)]
            if message.authorization:
                self._memory.auths.add_reward(message.authorization, reward)
            if message.src_service:
                host.services_ucb.add_reward(message.src_service, reward)
        self._submodules.list[0].calculate_ucb(0)
        self._submodules.recalc(False)
    
    def process_error_message(self, message: Response, action: AttackerAction) -> None:
        if not isinstance(message.content, str):
            return
        if "local" in message.content and "service" in message.content:
            # yes, this will probably break at some point, but imho there's no better way
            self._memory.locality_discovered(IPAddress(message.src_ip), str(message._src_service))
        if "exploit" in message.content and "ocal" not in message.content:
            self._memory.exploit_not_applicable(action)
        if "enable session" in message.content:
            self._memory.no_session_creation(action)
    
    def log_ucbs(self) -> None:
        # divided into multiple functions + some code repetition to allow filtering in log config
        self.log_submodules()
        self.log_actions()
        self.log_hosts()
        self.log_auths()

    def log_submodules(self) -> None:
        for item in self._submodules.list:
            self.ucb_logger(item, Log.DEBUG)

    def log_actions(self) -> None:
        for item in self._memory.actions.list:
            self.ucb_logger(item, Log.DEBUG)

    def log_hosts(self) -> None:
        for item in self._memory.hosts_ucb.list:
            self.ucb_logger(item, Log.DEBUG)

    def log_auths(self) -> None:
        for item in self._memory.auths.list:
            self.ucb_logger(item, Log.DEBUG)

    def run(self) -> None:
        self.log_ucbs()
        if self._queue.empty():
            if not self._memory.found_target_service:
                self._scanner_submodule.bias = 0.0
            else:
                self._scanner_submodule.bias = -0.15
            self._submodules.sort()
            # self.msg_logger("asset value: " + str(self._submodules.best.asset_value), Log.DEBUG)
            self._submodules.best.act()
        if not self._queue.empty():
            req = self._queue.get()
            # self.msg_logger(req)
            self._messaging.send_message(req)

    def action_stats(self):
        return self._action_mapping, self._action_attempts

    def new_host(self, ip: IPAddress) -> None:
        self._memory.new_host(ip)

    def new_session(self, ip: IPAddress, session: Session) -> None:
        self._memory.new_session(ip, session)

    def add_router_manually(self, submodule_id: int, network: IPNetwork) -> None:
        self._submodules.list[0].value._targeter.add_router_manually(network)

    def all_data(self) -> List[Tuple[IPAddress, Any]]:
        return self._memory.all_data()


def create_attacker(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    attacker = ModularAttacker(msg, res, args)
    return attacker


service_description = ActiveServiceDescription(
    "ucb_attacker",
    "An attacker that selects action based on the UCB1 algorithm.",
    create_attacker
)
