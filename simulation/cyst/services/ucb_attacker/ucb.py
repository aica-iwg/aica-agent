from typing import Any, Iterator, List, Optional
from math import log, sqrt
from random import random


class UCBItem:
    def __init__(self, value: Any, bias: float, exploration_weight: float) -> None:
        self.value = value
        self.ucb1 = 0
        self.bias = bias
        self._reward = 0
        self._attempts = 0
        self._exploration_weight = exploration_weight

    def calculate_ucb(self, total_attempts: int) -> None:
        if self._attempts == 0:
            self.ucb1 = 10
            return
        self.ucb1 = self._reward / self._attempts
        self.ucb1 += self._exploration_weight * sqrt(log(total_attempts) / self._attempts)

    def add_reward(self, reward: float) -> None:
        self._attempts += 1
        self._reward += reward

    def add_reward_for_past(self, reward: float) -> None:
        self._reward += reward


class UCBAction(UCBItem):

    action_weight = 1
    auth_weight = 3
    host_weight = 2
    service_weight = 1

    def calculate_ucb(self, total_attempts: int) -> None:
        if not self.value.ready():
            self.ucb1 = -10
            return

        targeter = self.value._targeter

        action_score = targeter.action_score
        denominator = self.action_weight
        nominator = action_score * self.action_weight

        host_score = targeter.host_score
        if host_score is not None:
            denominator += self.host_weight
            nominator += host_score * self.host_weight

        service_score = targeter.service_score
        if service_score is not None:
            denominator += self.service_weight
            nominator += service_score * self.service_weight

        auth_score = targeter.auth_score
        if auth_score is not None:
            denominator += self.auth_weight
            nominator += auth_score * self.auth_weight
        
        self.value.calculate_asset_value()
        self.ucb1 = self.value.asset_value * nominator / denominator


class UCBList:

    def __init__(self, sort_probability: int = 1, exploration_weight: float = sqrt(2)) -> None:
        # I really don't like that if I want a sorted collection in python,
        # I have to use a list, never update the key, or make it from scratch...
        self.list = []
        self._attempts = 0
        self._sort_probability = sort_probability
        self.exploration_weight = exploration_weight

    def __iter__(self) -> Iterator[List]:
        return self.list.__iter__()

    def add_item(self, value: Any, bias: float = 0) -> bool:
        for item in self.list:
            if item.value == value:
                return False
        self.list.append(UCBItem(value, bias, self.exploration_weight))
        return True

    def add_action(self, value, bias: float = 0) -> bool:
        for item in self.list:
            if item.value == value:
                return False
        self.list.append(UCBAction(value, bias, self.exploration_weight))
        self.list[-1].calculate_ucb(self._attempts)
        return True

    def get_item_score(self, value: Any) -> Optional[float]:
        for item in self.list:
            if item.value == value:
                return item.ucb1
        return None

    def add_reward(self, value: Any, reward: float, past: bool = False) -> None:
        if not 0 <= reward <= 1:
            return
        self._attempts += 1
        for item in self.list:
            if item.value == value:
                if past:
                    item.add_reward_for_past(reward)
                else:
                    item.add_reward(reward)
            item.calculate_ucb(self._attempts)
        self.sort()

    def recalc(self, lazy: bool = True) -> None:
        for i in self.list:
            if i.ucb1 == -10 or not lazy:
                i.calculate_ucb(self._attempts)

    def sort(self) -> None:
        if random() < self._sort_probability:
            self.list.sort(key=lambda x: -(x.ucb1 + x.bias))

    @property
    def best(self) -> Any:
        return self.list[0].value
