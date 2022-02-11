from typing import Optional, Any, List
from netaddr import IPAddress

from cyst.api.logic.access import Authorization
from cyst.api.logic.exploit import Exploit
from cyst.api.network.session import Session
from cyst.api.logic.data import Data


class AttackerAction:
    @classmethod
    def process_item(cls, item: Any) -> str:
        if isinstance(item, IPAddress):
            return "ip:" + str(item)
        if isinstance(item, Authorization):
            return "auth:" + str(item.token)
        if isinstance(item, Session):
            return "sess:" + item.id
        if isinstance(item, Data):
            return "data:" + str(item.id)
        return str(item)

    def __init__(self, result: List[Any],
                 rit: str, ip: IPAddress,
                 service: Optional[str] = None,
                 session: Optional[Session] = None,
                 auth: Optional[Authorization] = None,
                 exploit: Optional[str] = None):
        self.orig_result = result
        self.result = [AttackerAction.process_item(x) for x in result] if isinstance(result, list) else result
        self.ip = ip
        self.rit = rit
        self.service = service
        self.session = session
        self.auth = auth
        self.exploit = exploit
    
    def __str__(self):
        return f"{self.rit} - {self.ip}/{self.service} Expl={self.exploit} Auth=" + (self.auth.identity+"-" if self.auth else "") + \
               AttackerAction.process_item(self.auth) + " Sess=" + AttackerAction.process_item(self.session) + \
               f" Result={self.result}"


class History:
    def __init__(self):
        self.history = []
        self.first_seen = {}

    def add(self, message: AttackerAction) -> None:
        new_stuff = [AttackerAction.process_item(message.ip), AttackerAction.process_item(message.session)]
        if isinstance(message.result, list):
            new_stuff.extend(message.result)
        for item in new_stuff:
            if item not in self.first_seen.keys():
                self.first_seen[item] = len(self.history)
        self.history.append(message)
    
    def source_of(self, item: Any) -> AttackerAction:
        key = AttackerAction.process_item(item)
        if key not in self.first_seen.keys():
            print("no source found for " + item)  # should never happen
        return self.history[self.first_seen[key]]

    def get_attack_path(self, item: Any) -> List[AttackerAction]:
        item = AttackerAction.process_item(item)
        required = [self.first_seen[item]]
        i = 0
        while i < len(required):
            action = self.history[required[i]]
            to_append = [self.first_seen[AttackerAction.process_item(action.ip)]]
            if action.service:
                to_append.append(self.first_seen["svc:" + action.service])
            if action.auth:
                to_append.append(self.first_seen[AttackerAction.process_item(action.auth)])
            if action.session:
                to_append.append(self.first_seen[AttackerAction.process_item(action.session)])
            required.extend(x for x in to_append if x and x not in required)
            i += 1
        required.sort()
        return [self.history[i] for i in required]
