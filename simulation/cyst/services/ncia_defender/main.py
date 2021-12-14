from typing import Tuple, Optional, Dict, Any

from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Message
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service


class NCIADefender(ActiveService):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._env = env
        self._res = res

    # This attacker only runs given actions. No own initiative
    def run(self):
        print("Launched an NCIA defender")

    def process_message(self, message: Message) -> Tuple[bool, int]:
        print ("Got a mesage at NCIA defender")

        return True, 1

    @staticmethod
    def cast_from(o: Service) -> 'NCIADefender':
        if o.active_service:
            # Had to do it step by step to shut up the validator
            service = o.active_service
            if isinstance(service, NCIADefender):
                return service
            else:
                raise ValueError("Malformed underlying object passed with the NCIADefender interface")
        else:
            raise ValueError("Not an active service passed")


def create_defender(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    defender = NCIADefender(msg, res, args)
    return defender


service_description = ActiveServiceDescription(
    "ncia_defender",
    "A defender that redirects to a honeypot",
    create_defender
)