import json
import os
import os.path
import time
from typing import Tuple, Optional, Dict, Any

from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Message, Request, MessageType
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service


class NCIADefender(ActiveService):
    def __init__(self, env: EnvironmentMessaging = None, res: EnvironmentResources = None, args: Optional[Dict[str, Any]] = None) -> None:
        self._env = env
        self._res = res
        self._redirected = False
        self._honeypot_ip = args["honeypot"]
        self._router_ip = args["router"]

    # This attacker only runs given actions. No own initiative
    def run(self):
        print("Launched an NCIA defender")

    def process_message(self, message: Message) -> Tuple[bool, int]:
        if message.type == MessageType.RESPONSE:
            return True, 1

        print ("Got a mesage at NCIA defender")

        if self._redirected:
          print("Attacker already redirected to the honeypot")
          return True, 1

        f = open("/var/log/suricata/eve.json", "a")

        if not f:
            raise RuntimeError("Could not open file for event sharing!")

        req = message.cast_to(Request)

        event = {
            "event_type": "alert",
            "alert": {
                "severity": 3,
                "signature_id": "*"
            },
            "src_ip": str(req.action.parameters["data"].value.src_ip),
            "dest_ip": str(req.action.parameters["data"].value.dst_ip)
        }

        evt_str = json.dumps(event)
        f.write(evt_str + "\n")
        print("Sending this fake suricata event:" + evt_str)
        f.close()

        # We are now waiting until we get a response
        file_path = "/var/log/suricata/response.json"
        got_response = False
        while not got_response:
          if not os.path.isfile(file_path):
            # active waiting for agent to react
            time.sleep(0.3)
          else:
            f = open(file_path, "r")
            text = f.readline()
            if not text == "honeypot":
              raise RuntimeError("Unknown response from the agent!")

            print("Got a request from agent to redirect to honeypot")
            got_response = True

            # send redirect action
            src_ip = req.action.parameters["data"].value.src_ip

            print("Defender got report of attacker at src_ip: " + str(src_ip))

            action = self._res.action_store.get("ncia:redirect")
            action.parameters["src_ip"].value= str(src_ip)
            action.parameters["dst_ip"].value = self._honeypot_ip

            r = self._env.create_request(self._router_ip, "", action)
            self._env.send_message(r)

            print("Sent a redirect request")

            self._redirected = 1

            f.close()
            os.unlink(file_path)

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
