from netaddr import *  # pylint: disable=unused-wildcard-import
from random import randint, choice, random
from typing import Optional

from cyst.services.ucb_attacker.target_selector import TargetSelector
from cyst.services.ucb_attacker.attacker_memory import AttackerMemory
from cyst.services.ucb_attacker.ucb import UCBList


class ScannedNetwork():
    def __init__(self, net: IPNetwork, mask_l: int = -1, mask_u: int = -1):
        self._net = net
        self._subnets = []
        if mask_l == -1:
            mask_l = self._net.prefixlen
        if mask_u == -1:
            mask_u = self._net.prefixlen
        self.mask_l = mask_l
        self.mask_u = mask_u

    def add_subnet(self, subnet) -> None:
        self._subnets.append(subnet)

    @property
    def first_address_int(self) -> int:
        intIP = int(self._net.ip)
        return intIP - (intIP % (2**self._net.prefixlen))

    @property
    def last_address_int(self) -> int:
        return self.first_address_int + len(self._net) - 1

    def is_fully_explored(self) -> bool:
        return sum(list(map(lambda x: len(x._net), self._subnets))) == len(self._net)

    def get_random_address(self) -> IPAddress:
        rnd = IPAddress(randint(self.first_address_int, self.last_address_int))
        if not self.is_fully_explored():
            while sum(list(map(lambda x: int(rnd in x._net), self._subnets))) != 0:
                rnd = IPAddress(randint(self.first_address_int, self.last_address_int))
        return rnd


class UCBSelector(TargetSelector):

    @property
    def host_score(self) -> Optional[float]:
        return None

    def __init__(self, attacker, net: IPNetwork):
        super().__init__(attacker._memory)
        self._attacker = attacker
        self._nets = UCBList(0.5)
        self._nets.add_item(ScannedNetwork(net))
        self._unknown_mask = []
        self._found = set()
        self._tested = set()
        self._rootnet = net
        self._priority = []

    def add_router_manually(self, router: IPNetwork):
        self._nets.add_item(ScannedNetwork(router))
        self._found.add(router.ip)

    def scanner(self) -> str:

        while self._priority:
            last_hashable = (self._priority[-1][0], self._priority[-1][1].id if self._priority[-1][1] else None)
            if self._priority[-1][0] in self._found or last_hashable in self._tested:
                self._priority.pop()
            else:
                self._host = self._priority[-1][0]
                self._last_scan = self._host
                self._tested.add(last_hashable)
                return str(self._host)

        randip = int(self._nets.best._net.ip)
        mask = self._nets.best._net.prefixlen
        randip -= randip % (2 ** (32 - mask))

        if (len(self._found) > 0):
            anotherip = int(choice(tuple(self._found)))
            randip += anotherip % (2 ** (32 - mask))

        attempts = 0
        look_for_leaves = random() < 0.5
        if look_for_leaves:
            mask = 24
        while (attempts == 0 or (IPAddress(randip), self.session().id if self.session() else None) in self._tested or IPAddress(randip) in self._found) and attempts < 10:
            attempts += 1
            for i in range(32 - mask):
                if (random() < 0.25 * (0.05 ** (i / (32 - mask)))):
                    randip ^= 2**i
        self._last_scan = IPAddress(randip)
        self._tested.add((self._last_scan, self.session().id if self.session() else None))
        self._host = self._last_scan
        return str(randip)

    def scan_result(self, successful: bool) -> None:
        reward = 0
        if successful:
            reward = 1
            self._found.add(self._last_scan)
            candidates = [int(self._last_scan) - 1, int(self._last_scan) + 1]
            for c in candidates:
                if c % 256 > 1:
                    self._priority.append((IPAddress(c), self.session()))
        self._nets.add_reward(self._nets.best, reward)
        self._attacker._memory.sessions.add_reward(self.session(), reward)
        if self._priority:
            self._priority.pop()

    def ready(self) -> bool:
        return True

    def session(self) -> bool:
        return self._attacker._memory.sessions.best if not self._priority else self._priority[-1][1]

    def host(self) -> str:
        return self._host
