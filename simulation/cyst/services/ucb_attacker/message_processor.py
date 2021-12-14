from netaddr import IPAddress

from cyst.services.ucb_attacker.attacker_memory import AttackerMemory
from cyst.api.environment.message import Response, StatusValue
from cyst.api.environment.resources import EnvironmentResources
from cyst.services.ucb_attacker.ucb_targeter import UCBSelector
from cyst.services.ucb_attacker.history import AttackerAction
from cyst.api.utils.logger import *  # pylint: disable=unused-wildcard-import


class MessageProcessor:
    
    msg_logger = Log.get_logger("msg")

    def __init__(self, mem: AttackerMemory) -> None:
        self._mem = mem
    
    def set_rit_and_submodule(self, rit: str, submodule) -> None:
        self._rit = rit
        self._submodule = submodule

    def process(self, message: Response, action: AttackerAction) -> bool:
        found_new_info = False
        if (message.src_ip is not None):
            found_new_info = found_new_info or self._mem.new_host(IPAddress(message.src_ip))
        if (message.session is not None):
            found_new_info |= self._mem.new_session(IPAddress(message.src_ip), message.session, message.session.endpoint.ip == IPAddress(message.src_ip))
        if (message._src_service is not None):
            self._mem.service_tested(IPAddress(message.src_ip), str(message._src_service), self._rit)

        if (self._rit == "aif:active_recon:service_discovery"):
            if (message.status.value == StatusValue.SUCCESS):
                for svc in message._content:
                    found_new_info |= self._mem.new_service(IPAddress(message.src_ip), str(svc))

        if (self._rit == "aif:active_recon:vulnerability_discovery"):
            if (message.status.value == StatusValue.SUCCESS):
                found_new_info |= self._mem.service_version(IPAddress(message.src_ip), str(message._src_service), message._content[0])

        if self._rit in ["aif:active_recon:information_discovery",
                         "aif:disclosure:data_exfiltration"]:
            if (message.status.value == StatusValue.SUCCESS and message._content is not None):
                for data in message._content:
                    # this also works for authorizations
                    found_new_info |= self._mem.new_data(IPAddress(message.src_ip), message._src_service, data, action)

        if self._rit.startswith("aif:ensure_access:command_and_control"):
            if (message.status.value == StatusValue.SUCCESS):
                found_new_info |= self._mem.new_view(IPAddress(message.src_ip), message._content)

        if self._rit == "aif:targeted_exploits:exploit_remote_services":
            for session in message.content:
                found_new_info |= self._mem.new_host(IPAddress(session.endpoint.ip))
                found_new_info |= self._mem.new_session(IPAddress(session.endpoint.ip), session)
                # found_new_info |= self._mem.new_session(None, session)

        if self._rit in ["aif:privilege_escalation:user_privilege_escalation",
                         "aif:privilege_escalation:root_privilege_escalation"]:
            if (message.status.value == StatusValue.SUCCESS):
                found_new_info |= self._mem.new_data(IPAddress(message.src_ip), message._src_service, message.authorization, action)
                self._mem.dont_repeat_rit_with_exploit(IPAddress(message.src_ip), str(message._src_service), self._submodule._targeter.exploit(), self._rit)

        if (self._rit == "aif:ensure_access:lateral_movement"):
            if (message.status.value == StatusValue.SUCCESS):
                self._mem.add_infected(IPAddress(message.src_ip))

        return found_new_info


class UCBSelectorProcessor(MessageProcessor):
    def __init__(self, selector: UCBSelector, mem: AttackerMemory) -> None:
        self._selector = selector
        self._mem = mem

    def process(self, message: Response, action: AttackerAction) -> bool:
        successful = message.status.value == StatusValue.SUCCESS
        target_ip = IPAddress(self._selector._last_scan)
        if successful and target_ip not in self._mem.hosts.keys():
            self._mem.new_host(target_ip)
            self._mem.hosts[target_ip].session = self._selector.session()
        self._selector.scan_result(successful)
        return successful
