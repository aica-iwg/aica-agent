from typing import List, Tuple, Union, Optional, Callable, Any
from netaddr import IPAddress  # pylint: disable=unused-wildcard-import
from semver import VersionInfo

from cyst.api.environment.stores import ExploitStore
from cyst.api.network.node import Node
from cyst.api.network.session import Session
from cyst.api.logic.access import Authorization, AccessLevel
from cyst.api.logic.data import Data
from cyst.api.logic.exploit import Exploit, ExploitLocality, ExploitCategory, ExploitParameterType

from cyst.api.utils.logger import *  # pylint: disable=unused-wildcard-import

from cyst.services.ucb_attacker.ucb import UCBList
from cyst.services.ucb_attacker.history import AttackerAction


class RitAuthCombinations:
    def __init__(self) -> None:
        self._dict = {}  # self._dict[rit] = [Auth]
    
    def action_executed(self, action: AttackerAction):
        if action.rit not in self._dict.keys():
            self._dict[action.rit] = []
        if action.auth in self._dict[action.rit]:
            return False
        self._dict[action.rit].append(action.auth)
        return True
    
    def action_undo(self, action: AttackerAction):
        if action.rit not in self._dict.keys():
            return False
        if action.auth not in self._dict[action.rit]:
            return False
        if action.auth in self._dict[action.rit]:
            self._dict[action.rit].remove(action.auth)
        return True

    def clear(self) -> None:
        self._dict.clear()

    def get_missing(self, rit: str, auths: List[Authorization], ignore: List[Authorization] = []) -> Optional[Authorization]:
        if rit not in self._dict.keys():
            self._dict[rit] = []
        used = self._dict[rit]

        for auth in auths:
            if auth not in used and auth not in ignore:
                # used.append(auth)
                return auth
        return None


class ExploitInfo:

    def __init__(self, name: str, svc: str, store: ExploitStore, local: bool) -> None:
        self._name = name
        self._exploit = store.get_exploit(id=self._name)[0]
        self._rit = []
        self._tested = RitAuthCombinations()
        self._tested_without_auth = []
        self.local = local
        self._add_rits()
        self.untested = True
        self.score = 0
        for param in self._exploit.parameters.values():
            if param.type == ExploitParameterType.IMPACT_IDENTITY and param.value == "ALL":
                self.score += 1
            elif param.type == ExploitParameterType.IMPACT_NODE and param.value == "ALL":
                self.score += 2
            elif param.type == ExploitParameterType.IMPACT_SERVICE and param.value == "ALL":
                self.score += 2
            elif param.type == ExploitParameterType.ENABLE_ELEVATED_ACCESS and param.value == "TRUE":
                self.score += 1
    
    def action_executed(self, action: AttackerAction) -> bool:
        self.untested = False
        if action.rit not in self._rit:
            return False
        if not action.auth:
            if action.rit in self._tested_without_auth:
                return False
            self._tested_without_auth.append(action.rit)
            return True
        return self._tested.action_executed(action)
    
    def action_undo(self, action: AttackerAction) -> bool:
        if action.rit not in self._rit:
            return False
        if not action.auth:
            if action.rit not in self._tested_without_auth:
                return False
            if action.rit in self._tested_without_auth:
                self._tested_without_auth.remove(action.rit)
            return True
        return self._tested.action_undo(action)

    def __str__(self):
        return self._name

    def get_untested_auth_for_rit(self, rit: str, auths: List[Authorization], no_reuse: List) -> Optional[Authorization]:
        if rit not in self._rit:
            return None
        a2 = []
        for a in auths:
            if a not in no_reuse:
                a2.append(a)
        return self._tested.get_missing(rit, a2)

    def _add_rits(self) -> None:
        # I think this method should be somewhere else (separate class?)
        # possibly unite some logic with environment/rit.py?

        # no condition needs to hold for these rits:
        self._rit.append("aif:ensure_access:command_and_control-a")
        self._rit.append("aif:ensure_access:command_and_control-e")
        self._rit.append("aif:targeted_exploits:exploit_remote_services")

        # information discovery
        if self._exploit.category == ExploitCategory.AUTH_MANIPULATION:
            self._rit.append("aif:active_recon:information_discovery")

        # privilege escalation
        if self._exploit.locality == ExploitLocality.LOCAL and self._exploit.category == ExploitCategory.AUTH_MANIPULATION:
            self._rit.append("aif:privilege_escalation:user_privilege_escalation")
            self._rit.append("aif:privilege_escalation:root_privilege_escalation")

    @property
    def name(self) -> Optional[str]:
        return self._name


class ServiceInfo:
    def __init__(self, name: str, is_target: bool, exploit_store: ExploitStore) -> None:
        self._name = name
        self.version = None
        self._tested = RitAuthCombinations()
        self.exploits = []
        self._store = exploit_store
        self.tested_rits = []
        self.local = False
        self.is_target = is_target
        self.invalid_auths = []
        self.session_creation = True
        for e in self._store.get_exploit(service=name):
            self.add_exploit(e.id, self._store, e.locality == ExploitLocality.LOCAL)
        self.exploits.sort(key=lambda x: 0 - x.score)
    
    def set_version(self, version_str: str) -> bool:
        tokens = version_str.split('-')
        self.version = VersionInfo.parse(tokens[-1])
        temp = self.exploits
        self.exploits = []
        for exploit in temp:
            exploit_service = self._store.get_exploit(exploit._name)[0].services.get(self._name, None)
            if exploit_service.min_version <= self.version <= exploit_service.max_version:
                self.exploits.append(exploit)
        return len(self.exploits) < len(temp)
    
    def action_executed(self, action: AttackerAction, error: Optional[str]) -> bool:
        if not action.exploit:
            return self._tested.action_executed(action)
        if self.version or error is None:
            return any([ei.action_executed(action) for ei in self.exploits])
        if error is not None and "authorization" in error:
            self.invalid_auths.append(action.auth)
        for ei in self.exploits:
            if ei.name == action.exploit:
                return ei.action_executed(action)
        return False
    
    def action_undo(self, action: AttackerAction) -> bool:
        if not action.exploit:
            return self._tested.action_undo(action)
        for ei in self.exploits:
            if ei.name == action.exploit:
                return ei.action_undo(action)
        return False

    def set_local(self) -> None:
        self.local = True

    def add_exploit(self, exploit: str, store: ExploitStore, local: bool) -> bool:
        if any([exploit == e.name for e in self.exploits]):
            return False
        self.exploits.append(ExploitInfo(exploit, self._name, store, local))
        return True

    def get_auth(self, rit: str, auths: UCBList) -> Optional[Authorization]:
        return self._tested.get_missing(rit, auths)

    def get_exploit_and_auth(self, rit: str, auths: UCBList, allow_local_exploits: bool, no_reuse: List) -> Tuple[Optional[Exploit], Optional[Authorization]]:
        for ei in self.exploits:
            if ei.local and not allow_local_exploits:
                continue
            auth = ei.get_untested_auth_for_rit(rit, auths, no_reuse + self.invalid_auths)
            if auth is not None:
                return (ei.name, auth)
        return None, None


class HostInfo:
    def __init__(self):
        self.services = {}
        self.services_ucb = UCBList()
        self.session = None
        self.got_local_session = False
        self.auths = []
        self._rit_tested_auth = {}
        self._elevated = False
        self.infection = AccessLevel.NONE
        self.locality_fails = []
    
    def action_executed(self, action: AttackerAction, error: Optional[str]) -> bool:
        if error is not None and isinstance(error, str) and "local" in error:
            self.locality_fails.append(action)
        if not action.service:
            if not action.auth:
                if action.rit in self._rit_tested_auth.keys():
                    return False
                self._rit_tested_auth[action.rit] = []
                return True
            if action.rit not in self._rit_tested_auth.keys():
                self._rit_tested_auth[action.rit] = [action.auth]
                return True
            if action.auth in self._rit_tested_auth[action.rit]:
                return False
            self._rit_tested_auth[action.rit].append(action.auth)
            return True
        if action.service not in self.services.keys():
            return False
        return self.services[action.service].action_executed(action, error)
    
    def action_undo(self, action: AttackerAction) -> bool:
        if not action.service:
            if not action.auth:
                if action.rit not in self._rit_tested_auth.keys():
                    return False
                self._rit_tested_auth.pop(action.rit, None)
                return True
            if action.rit not in self._rit_tested_auth.keys():
                return False
            if action.auth in self._rit_tested_auth[action.rit]:
                self._rit_tested_auth[action.rit].pop(action.auth)
                return True
            return False
        if action.service not in self.services.keys():
            return False
        return self.services[action.service].action_undo(action)

    def was_auth_tested(self, rit: str, auth: Authorization) -> bool:
        if auth is None:
            return rit in self._rit_tested_auth.keys()
        if rit not in self._rit_tested_auth.keys():
            self._rit_tested_auth[rit] = []
        if auth in self._rit_tested_auth[rit]:
            return True
        else:
            # self._rit_tested_auth[rit].append(auth)
            return False
    
    def get_auths(self, auths: UCBList) -> List[Authorization]:
        result = []
        for item in auths:
            if item.value in self.auths:
                result.append(item.value)
        return result

    def add_service(self, service_id: ServiceInfo, is_target: bool, exploit_store: ExploitStore, auth_sources: List[Tuple]) -> bool:
        if service_id in self.services.keys():
            return False
        self.services[service_id] = ServiceInfo(service_id, is_target, exploit_store)
        service = self.services[service_id]
        for auth_source in auth_sources:
            if not auth_source[3] and service._name != auth_source[1].service:
                service.invalid_auths.append(auth_source[0])
        return True

    def add_auth(self, auth_source: Tuple) -> None:
        self.auths.append(auth_source[0])
        for service in self.services.keys():
            if not auth_source[3] and service != auth_source[1].service:
                self.services[service].invalid_auths.append(auth_source[0])

    def ready_for_rit(self, rit: str) -> bool:
        if rit == "aif:ensure_access:lateral_movement" \
           and (self.infection == AccessLevel.ELEVATED or (self.infection == AccessLevel.LIMITED and not self._elevated)):
            return False
        if rit in ["aif:privilege_escalation:user_privilege_escalation",
                   "aif:privilege_escalation:root_privilege_escalation",
                   "aif:ensure_access:lateral_movement"] \
                and self.session is None:
            return False
        if "command_and_control" in rit and self.got_local_session:
            return False
        return True
    
    def local_session_found(self) -> None:
        if self.got_local_session:
            return
        self.got_local_session = True
        for action in self.locality_fails:
            self.action_undo(action)


class AttackerMemory:

    def __init__(self, attacker) -> None:
        self.hosts = {}
        self.hosts_ucb = UCBList()
        self.data = []
        self.actions = UCBList()
        self.auths = UCBList()
        self.sessions = UCBList()
        self.sessions.add_item(None)
        self._no_reuse = []
        self._attacker = attacker
        self.found_target_service = False
        self.auth_sources = []

    def new_view(self, host: IPAddress, view) -> bool:
        return False
        # self.hosts[host].view = view

    def new_session(self, host: Optional[IPAddress], session: Session, local: bool = False) -> bool:
        if session is None:
            return False
        if host is not None and host in self.hosts.keys():
            self.hosts[host].session = session
            if local:
                self.hosts[host].local_session_found()
        for s in self.sessions:
            if s.value is None:
                continue
            if s.value.id == session.id:
                return False
        self.sessions.add_item(session)
        return True

    def get_session(self, host: IPAddress) -> Optional[Session]:
        if host not in self.hosts.keys():
            return None
        return self.hosts[host].session

    def service_tested(self, host: IPAddress, service: str, rit: str) -> bool:
        if host not in self.hosts.keys():
            return False
        host = self.hosts[host]
        if service not in host.services.keys():
            return False
        if rit not in host.services[service].tested_rits:
            host.services[service].tested_rits.append(rit)
    
    def locality_discovered(self, host: IPAddress, service: str) -> bool:
        if host not in self.hosts.keys():
            return False
        host = self.hosts[host]
        if service not in host.services.keys():
            return False
        host.services[service].set_local()
    
    def action_executed(self, action: AttackerAction, error: Optional[str] = None) -> bool:
        if action.ip not in self.hosts.keys():
            return False
        host = self.hosts[action.ip]
        return host.action_executed(action, error)
    
    def action_undo(self, action: AttackerAction) -> bool:
        if action.ip not in self.hosts.keys():
            return False
        host = self.hosts[action.ip]
        return host.action_undo(action)

    def get_data(self, rit: str,
                 host_condition: Callable,
                 service_condition: Optional[Callable] = None,
                 return_exploit: bool = False,
                 return_auth: bool = False):
        for host_key in self.hosts_ucb:
            host = self.hosts[host_key.value]
            if not host_condition(host):
                continue

            if service_condition is not None:
                for service_key in host.services_ucb:
                    service = host.services[service_key.value]
                    if service.local and not host.got_local_session:
                        continue
                    if not service_condition(service):
                        continue
                    if self.is_only_target_rit(rit) and not service.is_target:
                        continue
                    if "command" in rit and not service.session_creation:
                        continue
                    if not return_exploit:
                        if not return_auth:
                            return host_key.value, service_key.value
                        else:
                            auth = service.get_auth(rit, host.get_auths(self.auths))
                            if auth is not None:
                                return host_key.value, service_key.value, auth
                    else:
                        if not return_auth:
                            for exploit in service.exploits:
                                if exploit.local and not host.got_local_session:
                                    continue
                                if rit not in exploit._tested_without_auth and rit in exploit._rit:
                                    return host_key.value, service_key.value, exploit._name
                        else:
                            exploit, auth = service.get_exploit_and_auth(rit, host.get_auths(self.auths), host.got_local_session, self._no_reuse)
                            if exploit is not None:
                                return host_key.value, service_key.value, exploit, auth

            elif return_auth:
                for auth in host.get_auths(self.auths):
                    if auth.value is not None and not host.was_auth_tested(rit, auth.value):
                        return host_key.value, auth.value
            else:
                if not host.was_auth_tested(rit, None):
                    # host._rit_tested_auth[rit] = []
                    return host_key.value

        return_value = [None]
        if service_condition is not None:
            return_value.append(None)
        if return_auth:
            return_value.append(None)
        if return_exploit:
            return_value.append(None)
        return tuple(return_value) if len(return_value) > 1 else None
    
    def is_only_target_rit(self, rit: str) -> bool:
        return ("data" in rit)

    def all_exploits(self) -> List[Tuple[IPAddress, str, str]]:
        to_ret = []
        for host_key in self.hosts.keys():
            host = self.hosts[host_key]
            for service_key in host.services.keys():
                service = host.services[service_key]
                for exploit in service.exploits:
                    to_ret.append((host_key, service_key, str(exploit)))
        return to_ret

    def all_auths(self) -> List[Authorization]:
        return list(map(lambda x: x.value, self.auths))

    def all_data(self) -> List[Tuple[IPAddress, Any]]:
        return self.data

    def new_host(self, ip: IPAddress) -> bool:
        if ip in self.hosts.keys():
            return False
        self.hosts_ucb.add_item(ip)
        self.hosts[ip] = HostInfo()
        host = self.hosts[ip]
        for auth in self.auth_sources:
            if auth[2] or ip == auth[1].ip:
                host.add_auth(auth)
        return True

    def new_service(self, ip: IPAddress, service: str) -> bool:
        if ip not in self.hosts.keys() or "attacker" in service:
            return False
        host = self.hosts[ip]
        host.services_ucb.add_item(service)
        is_target = False
        for target in self._attacker.target_services:
            if target in service:
                is_target = True
                break
        if is_target:
            self.found_target_service = True
        return host.add_service(service, is_target, self._attacker._exploit_store, [x for x in self.auth_sources if x[2] or x[1].ip == ip])

    def new_exploit(self, host_id: IPAddress, service_id: str, exploit: str) -> bool:
        if host_id not in self.hosts.keys():
            return False
        host = self.hosts[host_id]
        if service_id not in host.services.keys():
            return False
        service = host.services[service_id]
        return service.add_exploit(exploit)

    def new_data(self, host_id: IPAddress, service_id: str, data: Union[str, Data, Authorization], source_action: AttackerAction) -> bool:
        if host_id not in self.hosts.keys():
            return False

        if (isinstance(data, Authorization)):
            for auth in self.auths:
                if self.auth_compare(data, auth.value):
                    return False
            self.new_auth(data, source_action)
            """
            for host_key in self.hosts.keys():
                # !!! MISSING CODE !!!
                host = self.hosts[host_key]
                host.add_auth(data)
            """
            self.auths.add_item(data)
            
            return True
        data_tuple = (host_id, data)
        if data_tuple not in self.data:
            self.data.append(data_tuple)
        return True
    
    def new_auth(self, auth: Authorization, source: AttackerAction) -> None:
        exploit_name = source.exploit
        any_node = True
        any_service = True
        
        if exploit_name and "privilege" in source.rit:
            exploit = self._attacker._exploit_store.get_exploit(id=exploit_name)[0]
            any_node = False
            any_service = False
            for param in exploit.parameters.values():
                if param.type == ExploitParameterType.IMPACT_NODE and param.value == "ALL":
                    any_node = True
                elif param.type == ExploitParameterType.IMPACT_SERVICE and param.value == "ALL":
                    any_service = True
        if exploit_name and "command" in source.rit:
            any_node = False
            # the authorization also works on the shell of the node, and there's no way to tell which service it is :(
        
        self.auth_sources.append((auth, source, any_node, any_service))
        for host_key in self.hosts.keys():
            if any_node or host_key == source.ip:
                self.hosts[host_key].add_auth(self.auth_sources[-1])
    
    def service_version(self, host_key: IPAddress, service_key: str, version: str) -> bool:
        if host_key not in self.hosts.keys():
            return False
        host = self.hosts[host_key]
        if service_key not in host.services.keys():
            return False
        service = host.services[service_key]
        return service.set_version(version)
    
    def exploit_not_applicable(self, message: AttackerAction) -> None:
        if message.ip not in self.hosts.keys():
            return False
        host = self.hosts[message.ip]
        if message.service not in host.services.keys():
            return False
        service = host.services[message.service]
        service.exploits = [exploit for exploit in service.exploits if exploit._name != message.exploit]
    
    def no_session_creation(self, message: AttackerAction) -> None:
        if message.ip not in self.hosts.keys():
            return False
        host = self.hosts[message.ip]
        if message.service not in host.services.keys():
            return False
        service = host.services[message.service]
        service.session_creation = False

    def add_infected(self, infected_host: IPAddress, access_level: AccessLevel = AccessLevel.NONE) -> None:
        if infected_host in self.hosts.keys():
            self.hosts[infected_host].infection = access_level
    
    def dont_repeat_rit_with_exploit(self, host_key: IPAddress, service_key: str, exploit_name: str, rit: str) -> None:
        if host_key not in self.hosts.keys():
            return
        host = self.hosts[host_key]
        if service_key not in host.services.keys():
            return
        service = host.services[service_key]
        for exploit in service.exploits:
            if exploit._name == exploit_name:
                exploit._rit.remove(rit)
                break

    def auth_compare(self, a1: Authorization, a2: Authorization) -> bool:
        return (
            a1 is not None and
            a2 is not None and
            a1.identity == a2.identity and
            a1.nodes == a2.nodes and
            a1.services == a2.services and
            a1.access_level == a2.access_level
        )
