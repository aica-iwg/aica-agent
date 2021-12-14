import random
import math
from datetime import datetime

from abc import ABC, abstractmethod
from flags import Flags
from typing import Tuple, Any, Union, List, Optional, Dict
from netaddr import *

from cyst.api.logic.action import Action
from cyst.api.logic.access import Authorization, AccessLevel
from cyst.api.logic.data import Data
from cyst.api.logic.exploit import ExploitCategory
from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Request, Response, MessageType, Message, Status, StatusValue, StatusOrigin
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.network.session import Session
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service


# Linear congruential generator - thanks Thomas Lux @ StackOverflow
def random_range(start, stop=None, step=None):
    # Set a default values the same way "range" does.
    if stop is None:
        stop = start
        start = 0
    if step is None:
        step = 1
    # Use a mapping to convert a standard range into the desired range.
    mapping = lambda i: (i * step) + start
    # Compute the number of numbers in this range.
    maximum = (stop - start) // step
    # Seed range with a random integer.
    value = random.randint(0, maximum)
    #
    # Construct an offset, multiplier, and modulus for a linear
    # congruential generator. These generators are cyclic and
    # non-repeating when they maintain the properties:
    #
    #   1) "modulus" and "offset" are relatively prime.
    #   2) ["multiplier" - 1] is divisible by all prime factors of "modulus".
    #   3) ["multiplier" - 1] is divisible by 4 if "modulus" is divisible by 4.
    #
    offset = random.randint(0, maximum) * 2 + 1      # Pick a random odd-valued offset.
    multiplier = 4*(maximum//4) + 1                  # Pick a multiplier 1 greater than a multiple of 4.
    modulus = int(2**math.ceil(math.log2(maximum)))  # Pick a modulus just big enough to generate all numbers (power of 2).
    # Track how many random numbers have been returned.
    found = 0
    while found < maximum:
        # If this is a valid value, yield it in generator fashion.
        if value < maximum:
            found += 1
            yield mapping(value)
        # Calculate the next value in the sequence.
        value = (value*multiplier + offset) % modulus


class AttackStats:
    def __init__(self):
        self.start_time = datetime.fromtimestamp(0)
        self.end_time = datetime.fromtimestamp(0)
        self.sessions = 0
        self.auths = 0
        self.node_successes = 0
        self.service_successes = 0
        self.network_failures = 0
        self.node_failures = 0
        self.service_failures = 0
        self.network_errors = 0
        self.node_errors = 0
        self.service_errors = 0
        self.total = 0

    def __str__(self) -> str:
        result = "Attack start: " + self.start_time.strftime("%c")
        result += ", Attack end: " + self.end_time.strftime("%c")
        result += ", Active sessions: " + str(self.sessions)
        result += ", Authorization tokens: " + str(self.auths)
        result += ", (NODE, SUCCESS): " + str(self.node_successes)
        result += ", (NODE, FAILURE): " + str(self.node_failures)
        result += ", (NODE, ERROR): " + str(self.node_errors)
        result += ", (SERVICE, SUCCESS): " + str(self.service_successes)
        result += ", (SERVICE, FAILURE): " + str(self.service_failures)
        result += ", (SERVICE, ERROR): " + str(self.service_errors)
        result += ", (NETWORK, FAILURE): " + str(self.network_failures)
        result += ", (NETWORK, ERROR): " + str(self.network_errors)
        result += ", TOTAL: " + str(self.total)

        return result


class ReductionStrategy(Flags):
    NO_STRATEGY = (),
    NO_DUPLICATE_ACTIONS = (),
    LIVE_TARGETS_ONLY = (),
    KNOWN_SERVICES_ONLY = ()


class RandomAttackerControl(ABC):
    @abstractmethod
    def set_action_limit(self, value: int) -> None:
        pass

    @abstractmethod
    def set_reduction_strategy(self, strategy: ReductionStrategy) -> None:
        pass

    @abstractmethod
    def set_action_namespace(self, namespace: str) -> None:
        pass

    @abstractmethod
    def set_services(self, *service: str) -> None:
        pass

    @abstractmethod
    def add_sessions(self, *session: Session) -> None:
        pass

    @abstractmethod
    def add_auths(self, *auth: Authorization) -> None:
        pass

    @abstractmethod
    def add_target(self, *target: str) -> None:
        pass

    @abstractmethod
    def add_targets(self, net: IPNetwork) -> None:
        pass

    @abstractmethod
    def set_goal(self, goal: str) -> None:
        pass

    @abstractmethod
    def attack_stats(self) -> Tuple[AttackStats, List[Session], List[Authorization], Tuple[Response, Action]]:
        pass

    @abstractmethod
    def attack_stats_str(self) -> str:
        pass

    @abstractmethod
    def reset(self) -> None:
        pass

    @abstractmethod
    def run(self) -> None:
        pass


class RandomAttacker(ActiveService, RandomAttackerControl):
    def __init__(self, msg: EnvironmentMessaging = None, res: EnvironmentResources = None) -> None:
        # super(RandomAttacker, self).__init__(id, msg, res)

        self._messaging = msg

        self._actions = None
        self._exploits = None
        self._targets = None
        self._services = None
        self._sessions = None
        self._session_ids = None
        self._auths = None
        self._auth_tokens = None

        self._goal = None
        self._action_limit = None
        self._action_count = None

        self._strategy = None

        self._activity_sources = None
        self._activity_order = None
        self._activity_factors = None
        self._used_activities = None

        self._tss = None
        self._tses = None
        self._tser = None

        self._removed_targets = None
        self._removed_tss = None
        self._removed_tses = None
        self._removed_tser = None

        self._last_action = None
        self._last_response = None
        self._achieved_goal = None
        self._reached_limit = None

        self._attack_stats = None
        self._successes = None

        self._test_mode = None

        self._action_store = res.action_store
        self._exploit_store = res.exploit_store

        self.reset()

    def reset(self) -> None:
        self._actions = []
        self._exploits = [None]
        self._targets = []
        self._services = [None]
        self._sessions = [None]
        self._session_ids = set()
        self._auths = [None]
        self._auth_tokens = set()

        self._goal = None
        self._action_limit = 0
        self._action_count = 0

        self._strategy = ReductionStrategy.NO_STRATEGY

        self._activity_sources = []
        self._activity_order = None
        self._activity_factors = []
        self._used_activities = set()

        self._tss = []
        self._tses = []
        self._tser = []

        self._removed_targets = set()
        self._removed_tss = set()
        self._removed_tses = set()
        self._removed_tser = set()

        self._last_action = None
        self._last_response = None
        self._achieved_goal = False
        self._reached_limit = False

        self._attack_stats = AttackStats()
        self._successes = []

        self._test_mode = False

    def set_action_limit(self, value: int) -> None:
        self._action_limit = value

    def set_reduction_strategy(self, strategy: ReductionStrategy) -> None:
        if not strategy:
            self._strategy = ReductionStrategy.NO_STRATEGY
            self._activity_sources = [self._actions, self._exploits, self._targets, self._services, self._sessions,
                                      self._auths]
            return

        # The reduction strategy dictates the activity sources
        # No strategy, no duplicates: [actions, exploits, targets, services, sessions, auths]
        # only live addresses: [actions, exploits, (targets + sessions), services, auths]
        # only known services: [actions, exploits, (targets + services), sessions, auths]
        # only known services of live addresses: [actions, exploits, (targets + services + sessions), auths]
        self._strategy = strategy

        if strategy & ReductionStrategy.LIVE_TARGETS_ONLY and strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            self._activity_sources = [self._actions, self._exploits, self._tss, self._auths]
        elif strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
            self._activity_sources = [self._actions, self._exploits, self._tses, self._services, self._auths]
        elif strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            self._activity_sources = [self._actions, self._exploits, self._tser, self._sessions, self._auths]
        else:
            self._activity_sources = [self._actions, self._exploits, self._targets, self._services, self._sessions, self._auths]

    def set_action_namespace(self, namespace: str) -> None:
        self._actions = self._action_store.get_prefixed(namespace)
        if not self._actions:
            raise RuntimeError("No action in namespace {}".format(namespace))

    def add_action(self, action: Action) -> None:
        self._actions.append(action)

    def set_services(self, *service: str) -> None:
        self._services = [*service]
        self._services.insert(0, None)

    def add_sessions(self, *session: Session) -> None:
        for s in session:
            if s.id not in self._session_ids:
                self._sessions.append(s)
                self._session_ids.add(s.id)

    def add_auths(self, *auth: Authorization) -> None:
        for a in auth:
            if a.token not in self._auth_tokens:
                self._auths.append(a)
                self._auth_tokens.add(a.token)

    def add_target(self, *target: str) -> None:
        for t in target:
            self._targets.append(t)

    def add_targets(self, net: IPNetwork) -> None:
        for host in net:
            self.add_target(str(host))

    def set_goal(self, goal: str) -> None:
        self._goal = goal

    def attack_stats(self) -> Tuple[AttackStats, List[Session], List[Authorization], Tuple[Response, Action]]:
        return self._attack_stats, self._sessions, self._auths, self._successes

    def attack_stats_str(self) -> str:
        self._attack_stats.sessions = len(self._sessions)
        self._attack_stats.auths = len(self._auths)
        stats = str(self._attack_stats)
        stats += ", Remaining targets: " + str(len(self._targets))
        result = "Attack stats: [{}]".format(stats)
        for sess in self._sessions:
            result += "\n" + str(sess)

        for auth in self._auths:
            result += "\n" + str(auth)

        result += "\nActions:"
        for m, a in self._successes:
            result += "\nID: {}, Action: {}, Target: {}, Service: {}, Session: {}, Auth: {}".format(m.id,
                                                                                                    a.tags[0].name,
                                                                                                    m.src_ip,
                                                                                                    m.src_service,
                                                                                                    m.session.id if m.session else "None",
                                                                                                    m.authorization.identity if m.authorization else "None")

        return result

    def _update_random_range(self) -> None:
        self._activity_factors.clear()

        # Updating random range will create a new random range with new maximum given as a multiplication of lengths
        # of source lists, and create new factors to correctly calculate indexes from random numbers

        maximum = 1
        for i in range(len(self._activity_sources) - 1, -1, -1):
            self._activity_factors.insert(0, maximum)
            maximum *= len(self._activity_sources[i])

        self._activity_order = random_range(maximum)

    def _number_to_index(self, val: int) -> Tuple[Union[int, Any], ...]:
        indices = []
        for i in range(len(self._activity_sources)):
            factor = self._activity_factors[i]
            index_i = val // factor
            val -= index_i * factor

            indices.append(index_i)

        return tuple(indices)

    def _add_session(self, s: Session) -> None:
        if not s:
            return

        # Sessions to already available endpoint are discarded, otherwise it would explode the action space with no gain
        for session in self._sessions:
            if session and s.end == session.end:
                return

        self._sessions.append(s)
        session_index = len(self._sessions) - 1

        if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            # if both live targets and known services are required, then adding a session has to add all discarded
            # targets with new session and empty service. New triplets from _tss are also added.
            new_tss = []
            for item in self._tss:
                # target, service, session
                new_item = (item[0], item[1], session_index)
                new_tss.append(new_item)
            self._tss.extend(new_tss)

            if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
                new_tss = []
                for tss in self._removed_tss:
                    # Target, None service, session
                    new_item = (tss[0], 0, session_index)
                    new_tss.append(new_item)
                self._tss.extend(new_tss)

        elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
            # If only live targets are required, then adding a session adds new (target, session) tuples for both
            # the existing _tses and for _removed_tses
            if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
                new_tses = []
                for tses in self._tses:
                    # Target, None service, session
                    new_item = (tses[0], session_index)
                    new_tses.append(new_item)
                self._tses.extend(new_tses)

                new_tses = []
                for tses in self._removed_tses:
                    # Target, None service, session
                    new_item = (tses[0], session_index)
                    new_tses.append(new_item)
                self._tses.extend(new_tses)

            else:
                for index, target in enumerate(self._targets):
                    new_item = (index, session_index)
                    self._tses.append(new_item)

        # If only known services are required or there is no reduction strategy, then session is only added to the
        # _sessions store

        # Addition is ok, just stretch the random range
        if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
            self._update_random_range()

    def _add_auth(self, a: Authorization) -> None:
        if not a or a in self._auths:
            return

        self._auths.append(a)

        # Addition is ok, just stretch the random range
        # Other strategies are not affected
        if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
            self._update_random_range()

    def _add_service(self, target: str, service: str) -> None:
        target_index = -1
        for i, t in enumerate(self._targets):
            if t == target:
                target_index = i
                break

        service_index = -1
        for i, s in enumerate(self._services):
            if s == service:
                service_index = i
                break

        # Adding services is only used for strategies, which include .KNOWN_SERVICE_ONLY
        if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            # It is not necessary to update removed targets, only add new tss with given service
            sessions = set()
            found = False
            for tss in self._tss:
                if tss[0] == target_index:
                    if tss[1] == service_index:
                        found = True
                        break
                    else:
                        if tss[2] not in sessions:
                            sessions.add(tss[2])
            if not found:
                for s in sessions:
                    self._tss.append((target_index, service_index, s))

        elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            # It is not necessary to update removed targets, only add new tss with given service
            found = False
            for tser in self._tser:
                if tser[0] == target_index and tser[1] == service_index:
                    found = True
                    break
            self._tser.append((target_index, service_index))

        # Addition is ok, just stretch the random range
        if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
            self._update_random_range()

    def _remove_target(self, target: str, session: Optional[Session]) -> None:
        # First of all find the index of both target and session
        target_index = -1
        for i, t in enumerate(self._targets):
            if t == target:
                target_index = i
                break

        session_index = -1
        # Checking just session ids is ok, because there is no situation, when new session would lead to target removal
        if not session:
            session_index = 0
        else:
            for i, s in enumerate(self._sessions):
                if s and s.id == session.id:
                    session_index = i
                    break

        # If there is a requirement for non-duplicate actions, then go through sources containing targets and add the to
        # filter pools
        if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
            if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                filter_tss = [x for x in self._tss if (x[0] == target_index and x[2] == session_index)]
                self._removed_tss.update(filter_tss)
            elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
                filter_tses = [x for x in self._tses if (x[0] == target_index and x[1] == session_index)]
                self._removed_tses.update(filter_tses)
            elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                filter_tser = [x for x in self._tser if x[0] == target_index]
                self._removed_tser.update(filter_tser)
            else:
                self._removed_targets.add(target_index)
        # If there is no requirement for non-duplicate actions, then it is easy, just remove the target and its tuples
        else:
            if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                self._tss[:] = [x for x in self._tss if (x[0] != target_index or x[2] != session_index)]
            elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
                self._tses[:] = [x for x in self._tses if (x[0] != target_index or x[1] != session_index)]
            elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                self._tser[:] = [x for x in self._tser if x[0] != target_index]
            else:
                del self._targets[target_index]

    def enable_test(self) -> None:
        self._test_mode = True

    def run(self) -> None:
        if not self._actions or not self._targets:
            raise RuntimeError("Either no actions or no targets were provided")

        # Fill exploits only when the exploit store is surely full
        for cat in ExploitCategory:
            self._exploits.extend(self._exploit_store.get_exploit(category=cat))

        # Prepare targets for the attacker
        if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            for i in range(0, len(self._targets)):
                for k in range(0, len(self._sessions)):
                    self._tss.append((i, 0, k))
        elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
            for i in range(0, len(self._targets)):
                for k in range(0, len(self._sessions)):
                    self._tses.append((i, k))
        elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
            for i in range(0, len(self._targets)):
                self._tser.append((i, 0))

        if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
            self._update_random_range()

        else:
            self._attack_stats.start_time = datetime.now()
            self.execute_action(*self.get_next_action())
            self._action_count += 1

    def execute_action(self, target: str, service: str, action: Action, session: Session = None, authorization: Authorization = None) -> None:
        request = self._messaging.create_request(target, service, action, session=session, auth=authorization)
        self._last_action = action
        self._messaging.send_message(request)

    def get_next_action(self) -> Tuple[str, str, Action, Session, Authorization]:
        if self._strategy & ReductionStrategy.NO_DUPLICATE_ACTIONS:
            while True:
                indices = self._number_to_index(next(self._activity_order))
                if indices in self._used_activities:
                    continue
                if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                    subindices = self._tss[indices[2]]
                    if subindices in self._removed_tss:
                        continue
                    else:
                        break
                elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
                    subindices = self._tses[indices[2]]
                    if subindices in self._removed_tses:
                        continue
                    else:
                        break
                elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                    subindices = self._tser[indices[2]]
                    if subindices in self._removed_tser:
                        continue
                    else:
                        break
                else:
                    break

            self._used_activities.add(indices)

            action = self._actions[indices[0]]
            exploit = self._exploits[indices[1]]

            if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                target = self._targets[self._tss[indices[2]][0]]
                service = self._services[self._tss[indices[2]][1]]
                session = self._sessions[self._tss[indices[2]][2]]
                auth = self._auths[indices[3]]
            elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
                target = self._targets[self._tses[indices[2]][0]]
                session = self._sessions[self._tses[indices[2]][1]]
                service = self._services[indices[3]]
                auth = self._auths[indices[4]]
            elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                target = self._targets[self._tser[indices[2]][0]]
                service = self._services[self._tser[indices[2]][1]]
                session = self._sessions[indices[3]]
                auth = self._auths[indices[4]]
            else:
                target = self._targets[indices[2]]
                service = self._services[indices[3]]
                session = self._sessions[indices[4]]
                auth = self._auths[indices[5]]

        else:
            action = random.choice(self._actions)
            exploit = random.choice(self._exploits)

            if self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY and self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                x = random.choice(self._tss)
                target = self._targets[x[0]]
                service = self._services[x[1]]
                session = self._sessions[x[2]]
            elif self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
                x = random.choice(self._tses)
                target = self._targets[x[0]]
                session = self._sessions[x[1]]
                service = random.choice(self._services)
            elif self._strategy & ReductionStrategy.KNOWN_SERVICES_ONLY:
                x = random.choice(self._tser)
                target = self._targets[x[0]]
                service = self._services[x[1]]
                session = random.choice(self._sessions)
            else:
                target = random.choice(self._targets)
                service = random.choice(self._services)
                session = random.choice(self._sessions)

            auth = random.choice(self._auths)

        if exploit:
            action.set_exploit(exploit)

        return target, service, action, session, auth

    def process_message(self, message: Response) -> Tuple[bool, int]:
        self._last_response = message

        if message.status == Status(StatusOrigin.SERVICE, StatusValue.SUCCESS):
            self._attack_stats.service_successes += 1
            self._attack_stats.total += 1
            self._successes.append((message, self._last_action))
        elif message.status == Status(StatusOrigin.SERVICE, StatusValue.FAILURE):
            self._attack_stats.service_failures += 1
            self._attack_stats.total += 1
        elif message.status == Status(StatusOrigin.SERVICE, StatusValue.ERROR):
            self._attack_stats.service_errors += 1
            self._attack_stats.total += 1
        elif message.status == Status(StatusOrigin.NODE, StatusValue.SUCCESS):
            self._attack_stats.node_successes += 1
            self._attack_stats.total += 1
        elif message.status == Status(StatusOrigin.NODE, StatusValue.FAILURE):
            self._attack_stats.node_failures += 1
            self._attack_stats.total += 1
        elif message.status == Status(StatusOrigin.NODE, StatusValue.ERROR):
            self._attack_stats.node_errors += 1
            self._attack_stats.total += 1
        elif message.status == Status(StatusOrigin.NETWORK, StatusValue.FAILURE):
            self._attack_stats.network_failures += 1
            self._attack_stats.total += 1
        elif message.status == Status(StatusOrigin.NETWORK, StatusValue.ERROR):
            self._attack_stats.network_errors += 1
            self._attack_stats.total += 1

        # Extract new sessions and auths
        s = message.session
        a = message.authorization
        c = message.content

        if message.status == Status(StatusOrigin.NETWORK, StatusValue.FAILURE) and self._strategy & ReductionStrategy.LIVE_TARGETS_ONLY:
            self._remove_target(str(message.src_ip), s)

        self._add_auth(a)
        self._add_session(s)

        if c and isinstance(c, list):
            for item in c:
                if isinstance(item, Data):
                    if self._goal:
                        if item.description in self._goal:
                            self._achieved_goal = True
                            break
                elif isinstance(item, Authorization):
                    if item not in self._auths:
                        self._add_auth(item)
                elif isinstance(item, str) and self._last_action.id == "aif:active_recon:service_discovery":
                    self._add_service(str(message.src_ip), item)
                elif isinstance(item, Session):
                    self._add_session(item)

        if not self._achieved_goal and self._action_count < self._action_limit:
            self.execute_action(*self.get_next_action())
            self._action_count += 1
        else :
            self._attack_stats.end_time = datetime.now()
            # print (">> Last action: {}, Last response: {}".format(self._last_action.tags[0].name, self._last_response))
            if not self._achieved_goal:
                self._reached_limit = True

        return True, 1


def create_attacker(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    attacker = RandomAttacker(msg, res)
    return attacker


service_description = ActiveServiceDescription(
    "random_attacker",
    "An attacker that performs random actions from given action namespace.",
    create_attacker
)