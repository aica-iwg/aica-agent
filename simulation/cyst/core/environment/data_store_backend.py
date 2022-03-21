from enum import Enum
from typing import Union, NewType, Any, Type, Dict
from abc import abstractmethod, ABC

from cyst.api.environment.message import Message, MessageType, Response, Request
from cyst.api.environment.stats import Statistics

from cyst.core.environment.message import MessageImpl

read_write_data = [Statistics]
write_only_data = [Message]
append_only_data = [Message]


# ----------------------------------------------------------------------------------------------------------------------
# These functions transform specific interfaces into dicts for storage in data store
def _statistics_to_dict(item: Statistics) -> Dict[str, Any]:
    result = dict()

    result["run_id"] = item.run_id
    result["configuration_id"] = item.configuration_id
    result["start_time_real"] = item.start_time_real
    result["end_time_real"] = item.end_time_real
    result["end_time_virtual"] = item.end_time_virtual

    return result


def _message_to_dict(item: Message) -> Dict[str, Any]:
    item: MessageImpl = MessageImpl.cast_from(item)
    result = dict()

    result["type"] = "REQUEST" if item.type == MessageType.REQUEST else "RESPONSE"
    result["id"] = item.id
    result["src_ip"] = str(item.src_ip)
    result["dst_ip"] = str(item.dst_ip)
    result["hop_src_ip"] = str(item.current.ip)
    result["hop_src_id"] = item.current.id
    result["hop_dst_ip"] = str(item.next_hop.ip)
    result["hop_dst_id"] = item.next_hop.id
    result["src_service"] = item.src_service
    result["dst_service"] = item.dst_service
    result["ttl"] = item.ttl

    if isinstance(item, Request):
        result["action"] = item.action.id
    else:
        result["action"] = ""

    if isinstance(item, Response):
        result["result"] = "{}|{}|{}".format(item.status.origin.name, item.status.value.name, item.status.detail.name)
    else:
        result["result"] = ""

    return result


def to_dict(item: Union[Statistics, Message]) -> Dict[str, Any]:
    if isinstance(item, Statistics):
        return _statistics_to_dict(item)
    if isinstance(item, Message):
        return _message_to_dict(item)
    else:
        raise RuntimeError("Attempting to convert an item of unknown type '{}' to dictionary.".format(type(item)))


# ----------------------------------------------------------------------------------------------------------------------
class DataStoreBackend:

    @abstractmethod
    def set(self, run_id: str, item: Any, item_type: Type, time: int = 0) -> None:
        pass

    @abstractmethod
    def get(self, run_id: str, item: Any, item_type: Type) -> Any:
        pass

    @abstractmethod
    def update(self, run_id: str, item: Any, item_type: Type) -> None:
        pass

    @abstractmethod
    def remove(self, run_id: str, item: Any, item_type: Type) -> None:
        pass

    @abstractmethod
    def clear(self, run_id: str) -> None:
        pass

    @abstractmethod
    def commit(self, run_id: str) -> None:
        pass

