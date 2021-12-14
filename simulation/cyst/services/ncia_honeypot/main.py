from typing import Optional, Dict, Any, Tuple

from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Request, Message, Status, StatusValue, StatusOrigin
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.host.service import ActiveService, ActiveServiceDescription


class LIHoneypot(ActiveService):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._env = env

    def run(self):
        pass

    def process_message(self, message: Message) -> Tuple[bool, int]:
        self._env.create_response(message.cast_to(Request), Status(StatusOrigin.SERVICE, StatusValue.SUCCESS), session=message.session, auth=message.auth)
        return True, 1


def create_honeypot(msg: EnvironmentMessaging, res: EnvironmentResources, args: Optional[Dict[str, Any]]) -> ActiveService:
    honeypot = LIHoneypot(msg, res, args)
    return honeypot


service_description = ActiveServiceDescription(
    "ncia_honeypot",
    "A honeypot service, which always returns success status",
    create_honeypot
)