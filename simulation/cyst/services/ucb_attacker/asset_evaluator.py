from netaddr import IPAddress, IPNetwork

from cyst.services.ucb_attacker.attacker_memory import AttackerMemory
from cyst.services.ucb_attacker.history import AttackerAction
from cyst.api.logic.access import Authorization, AccessLevel
from cyst.api.logic.exploit import Exploit, ExploitCategory, ExploitLocality, ExploitParameter, ExploitParameterType
from cyst.api.environment.stores import ExploitStore


class AssetEvaluator():

    @classmethod
    def evaluate(cls, source_action: AttackerAction, memory: AttackerMemory, exploit_store: ExploitStore) -> float:
        # the goal is to evaluate the asset that can be obtained by succeccfully using the action
        # the metrics used for the evaluation are:
        #  A = the number of new actions that are "unlocked" by obtaining this asset
        #  B = number of actions "saved" by (found to be unnecessary because of) this action
        #  R = amount of reward obtained
        # final formula is A + B + r*R, where r \in N

        reward_weight = 10  # r; go get the reward, I guess

        if source_action.rit == "aif:active_recon:host_discovery":
            # one action is unlocked: service discovery
            # ofc, more actions are unlocked later by that 1 action, but I don't want the attacker to spam this
            # so I'll only count immediately unlocked actions everywhere (makes me think less)
            # Howewer, setting this to 1 turned out to be too much in practice
            return 0.5
        
        if source_action.rit == "aif:active_recon:service_discovery":
            # idk? but the attacker always has to do it, so just return a big number?
            return reward_weight - 1  # but don't value it quite as high as finishing the scenario
        
        if source_action.rit == "aif:active_recon:vulnerability_discovery":
            # another weird one; doesn't technically unlock anything...
            # ... but it gives some information about whether usign an exploit is worth it
            # if there's only 1 possible exploit, just try the exploit right away, unless it's more likely to trigger the defender?
            # what to do if there are more possible exploits, though? for now, if there are >2 exploits for the action, return number of exploits
            # else, return 0, because it's not worth it
            # in the future, it would be nice if the attacker's knowledge base of exploits contained an info on what % of service installations is vulnerable
            # that would also be a nice starting point for UCB, an experienced hacker would have such information, and idk how you'd generate scenarios without that
            exploits = memory.hosts[source_action.ip].services[source_action.service].exploits
            exploit_count = sum((1 if e.untested else 0) for e in exploits)
            return 1.99 if exploit_count > 1 else 0
        
        if source_action.rit == "aif:active_recon:information_discovery":
            # can return just about anything... might even get a reward for it
            # authorization can only be used for data exfiltration, privilege escalation (only with exploit), and c&c
            exfiltration_actions = 0
            cc_actions = 0
            escalation_actions = 0
            for host_name, host in memory.hosts.items():
                if not host.got_local_session:
                    cc_actions += 1
                    # not going to add this per service, as you mostly want a session => only c&c once
                for service_name, service in host.services.items():
                    # this is slow btw
                    if service.is_target:
                        exfiltration_actions += 1
                        # test if the service was already attacked
                        for data in memory.data:
                            if data[0] == host_name and data[1] == service_name:
                                exfiltration_actions -= 1
                                break
                    exploits = exploit_store.get_exploit(service=source_action.service)
                    if host.got_local_session and exploits:
                        for exploit in exploits:
                            if exploit.locality == ExploitLocality.LOCAL and exploit.category == ExploitCategory.AUTH_MANIPULATION:
                                escalation_actions += 1
                                break
            
            # of course, the found auth might not be applicable, and there might not be a reward...
            # and honestly, this kind of reward will be found eventually, so weight = 0
            # have another 0 < magic number < 1
            return 5 + 0.4 * (exfiltration_actions + cc_actions + escalation_actions)
        
        if "privilege_escalation" in source_action.rit:
            any_user = False
            any_node = False
            any_service = False
            am_root = "root" in source_action.rit
            expl = exploit_store.get_exploit(source_action.exploit)[0]
            identity = "root"
            for param in expl.parameters.values():
                if param.type == ExploitParameterType.IMPACT_IDENTITY and param.value == "ALL":
                    any_user = True
                elif param.type == ExploitParameterType.IMPACT_NODE and param.value == "ALL":
                    any_node = True
                elif param.type == ExploitParameterType.IMPACT_SERVICE and param.value == "ALL":
                    any_service = True
                elif param.type == ExploitParameterType.IDENTITY:
                    identity = param.value

            # once again, the result is an auth, so stuff from above applies
            exfiltration_actions = 0
            cc_actions = 0
            escalation_actions = 0
            for host_name, host in memory.hosts.items():
                if IPAddress(host_name) != source_action.ip and not any_node:
                    continue
                for auth in host.auths:
                    if auth.access_level == AccessLevel.ELEVATED or auth.identity == identity:
                        continue
                if not host.got_local_session:
                    cc_actions += 1
                for service_name, service in host.services.items():
                    if service_name != source_action.service and not any_service:
                        continue
                    if service.is_target:
                        exfiltration_actions += 1
                        # test if the service was already attacked
                        for data in memory.data:
                            if data[0] == host_name and data[1] == service_name:
                                exfiltration_actions -= 1
                                break
                    exploits = exploit_store.get_exploit(service=source_action.service)
                    can_escalate = False
                    if host.got_local_session and exploits:
                        for exploit in exploits:
                            if can_escalate:
                                break
                            if exploit.locality == ExploitLocality.LOCAL and exploit.category == ExploitCategory.AUTH_MANIPULATION:
                                can_escalate = True
                    if can_escalate:
                        escalation_actions += 1

            # any_user and am_root should have some impact on whether the future actions are successful
            # how much impact? well, let's just introduce more 0 < magic numbers < 1
            # also, higher numbers than before, because I know more about where the auth will be used
            # that makes me somewhat more confident that the auth will actually work there ^^
            return (1.0 if am_root else (0.8 if any_user else 0.55)) * (exfiltration_actions + cc_actions + escalation_actions)

        if "command_and_control" in source_action.rit:  # -e,-a suffixes
            # assuming that I'm doing it mostly for the session
            # first, check whether I already have a session to the /24 network:
            net24 = IPNetwork(str(source_action.ip) + "/24")
            got_session_to_net24 = False
            for session in memory.sessions:
                if session.value and IPAddress(session.value.path[-1][1]) in net24:
                    got_session_to_net24 = True
                    break
            
            # next, check if there any local exploits on the host's services and if the services themselves are local:
            local_services = 0
            
            host = memory.hosts[source_action.ip]
            for key, service in host.services.items():
                if service.local:
                    local_services += 1
                    continue
                exploits = exploit_store.get_exploit(service=key)
                found_local_exploit = False
                for e in exploits:
                    if e.locality == ExploitLocality.LOCAL:
                        found_local_exploit = True
                        break
                if found_local_exploit:
                    local_services += 1
            
            # value of getting a new session to a /24 net should be, following the system, number of hosts that become reachable
            # let's just say it's 3 and worry about if only if it becomes a problem later on
            # also, add the number of services, because this action might save actions normally needed to determine they are local
            return (0 if got_session_to_net24 else 3) + (0 if host.got_local_session else 2 * local_services + len(host.services))

        if source_action.rit == "aif:disclosure:data_exfiltration":
            # value attacking the same service multiple times less:
            previous_attacks = 0
            for data in memory.data:
                if data[0] == source_action.ip and data[1] == source_action.service:
                    previous_attacks += 1
            return reward_weight * (2 / (2 + previous_attacks))
        
        # data_destruction will probably be result in a reward as well?
        # lateral movement - no idea
        
        if source_action.rit == "aif:targeted_exploits:exploit_remote_services":
            # I know literally nothing about what I'll get
            return 1
        
        return 1
