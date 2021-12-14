from typing import List, Optional, Tuple, Any, Dict

from cyst.api.logic.action import Action, ActionDescription, ActionParameter, ActionToken, ActionParameterDomain, ActionParameterDomainType
from cyst.api.logic.exploit import Exploit


class ActionParameterDomainImpl(ActionParameterDomain):

    def __init__(self, type: ActionParameterDomainType = ActionParameterDomainType.ANY,
                 range_min: int = -1, range_max: int = -1, range_step: int = -1, options: List[Any] = None,
                 default: Any = None):
        self._type = type
        self._default = default
        self._range_min = range_min
        self._range_max = range_max
        self._range_step = range_step
        if not options:
            self._options = []
        else:
            self._options = options

    @classmethod
    def bind_range(cls, default: int, range_min: int, range_max: int, range_step: int = 1) -> 'ActionParameterDomainImpl':
        return cls(ActionParameterDomainType.RANGE, range_min=range_min, range_max=range_max, range_step=range_step, default=default)

    @classmethod
    def bind_options(cls, default: Any, options: List[Any]) -> 'ActionParameterDomainImpl':
        return cls(ActionParameterDomainType.OPTIONS, options=options, default=default)

    @property
    def type(self) -> ActionParameterDomainType:
        return self._type

    @property
    def range_min(self) -> int:
        if self._type != ActionParameterDomainType.RANGE:
            raise AttributeError("Attempting to get lower range bound on a non-range domain")
        return self._range_min

    @property
    def range_max(self) -> int:
        if self._type != ActionParameterDomainType.RANGE:
            raise AttributeError("Attempting to get upper range bound on a non-range domain")
        return self._range_max

    @property
    def range_step(self) -> int:
        if self._type != ActionParameterDomainType.RANGE:
            raise AttributeError("Attempting to get range step on a non-range domain")
        return self._range_min

    @property
    def options(self) -> List[Any]:
        if self._type != ActionParameterDomainType.OPTIONS:
            raise AttributeError("Attempting to get options on a non-option domain")
        return self._options

    def validate(self, value: Any) -> bool:
        if self._type == ActionParameterDomainType.ANY:
            return True

        if self._type == ActionParameterDomainType.RANGE:
            if not isinstance(value, int):
                return False

            if value < self._range_min or value > self._range_max or (value - self._range_min) % self._range_step != 0:
                return False

            return True

        if self._type == ActionParameterDomainType.OPTIONS:
            if value in self._options:
                return True

            return False

    def default(self) -> Any:
        return self._default

    def __getitem__(self, item: int) -> Any:
        if self._type == ActionParameterDomainType.ANY:
            raise IndexError("Attempting to get value from unbounded domain")

        # __getitem__ gets item-th element from the number range
        if self._type == ActionParameterDomainType.RANGE:
            return self._range_min + item * self._range_step

        if self._type == ActionParameterDomainType.OPTIONS:
            return self._options[item]

    def __len__(self) -> int:
        if self._type == ActionParameterDomainType.ANY:
            raise ValueError("Unbounded domain has no length")

        if self._type == ActionParameterDomainType.RANGE:
            return (self._range_max - self._range_min) // self._range_step

        if self._type == ActionParameterDomainType.OPTIONS:
            return len(self._options)


class ActionImpl(Action):

    def __init__(self, action: ActionDescription):
        self._id = action.id
        fragments = action.id.split(":")
        self._namespace = fragments[0]
        self._fragments = fragments[1:]
        self._description = action.description
        self._tokens = action.tokens
        self._exploit = None
        self._parameters: Dict[str, ActionParameter] = {}
        for p in action.parameters:
            self._parameters[p.name] = p

    @property
    def id(self) -> str:
        return self._id

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def fragments(self) -> List[str]:
        return self._fragments

    @property
    def exploit(self) -> Exploit:
        return self._exploit

    def set_exploit(self, exploit: Optional[Exploit]) -> None:
        self._exploit = exploit

    @property
    def parameters(self) -> Dict[str, ActionParameter]:
        return self._parameters

    def add_parameters(self, *params: ActionParameter) -> None:
        for p in params:
            self._parameters[p.name] = p

    @property
    def tokens(self) -> List[Tuple[ActionToken, ActionToken]]:
        return self._tokens

    @staticmethod
    def cast_from(o: Action) -> 'ActionImpl':
        if isinstance(o, ActionImpl):
            return o
        else:
            raise ValueError("Malformed underlying object passed with the Action interface")

    def copy(self):
        return ActionImpl(ActionDescription(self.id, self._description, list(self._parameters.values()), self._tokens))
