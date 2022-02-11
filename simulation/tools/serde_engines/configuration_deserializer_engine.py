from typing import List, Dict, TextIO, Callable
from netaddr import IPAddress, IPNetwork


from cyst.api.configuration.configuration import ConfigItem
from cyst.api.configuration.logic.access import *
from cyst.api.configuration.logic.data import *
from cyst.api.configuration.logic.exploit import *
from cyst.api.configuration.host.service import *
from cyst.api.configuration.network.network import *
from cyst.api.configuration.network.node import *
from cyst.api.configuration.network.router import *
from cyst.api.configuration.network.firewall import *
from cyst.api.configuration.network.elements import *


class Deserializer:
    def __init__(self, file: TextIO, load_func: Callable):
        self._file = file
        self._items = []
        self._load_func = load_func

    def deserialize_file(self) -> List[ConfigItem]:
        self._traverse(self._load_func(self._file))
        return self._items

    def deserialize_data(self, data: str):  # make this option nicer nicer
        self._traverse(self._load_func(data))
        return self._items

    def _traverse(self, collection: Dict):
        for item in collection.values():
            self._items.append(self._process(item))

    def _process(self, sub_collection: Any):

        if isinstance(sub_collection, list) or isinstance(sub_collection, tuple):
            return [self._process(item) for item in sub_collection]

        if not isinstance(sub_collection, dict):
            return sub_collection

        cls_type = sub_collection.pop("cls_type", None)

        if cls_type is None:
            raise RuntimeError("cannot defer type, config serialized with inappropriate tool")

        if cls_type == 'NoneType':
            return None

        if cls_type == typename(IPAddress) or cls_type == typename(IPNetwork):
            return globals()[cls_type](sub_collection["value"]) if sub_collection.get("value") is not None else None

        for attribute_name, attribute_value in sub_collection.items():
            sub_collection[attribute_name] = self._process(attribute_value)

        return globals()[cls_type](**sub_collection)


def deserialize_toml(file: TextIO):
    from rtoml import load
    toml_deserializer = Deserializer(file, load)
    return toml_deserializer.deserialize_file()


def deserialize_json(file: TextIO):
    from json import load
    json_deserializer = Deserializer(file, load)
    return json_deserializer.deserialize_file()


def deserialize_yaml(file: TextIO):
    from yaml import safe_load
    yaml_deserializer = Deserializer(file, safe_load)
    return yaml_deserializer.deserialize_file()


def deserialize_gura(file: TextIO):
    from gura import loads
    gura_deserializer = Deserializer(file, loads)
    return gura_deserializer.deserialize_data(file.read())


