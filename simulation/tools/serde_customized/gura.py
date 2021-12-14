from typing import Type, Dict

import gura

from .compat import T
from .de import Deserializer, from_dict
from .se import Serializer, to_dict


class GuraSerializer(Serializer):
    @classmethod
    def serialize(cls, obj, **opts) -> str:
        return gura.dumps(obj, **opts)


class GuraDeserializer(Deserializer):
    @classmethod
    def deserialize(cls, s, **opts):
        return gura.loads(s, **opts)


def to_gura(obj, se: Type[Serializer] = GuraSerializer, **opts) -> str:

    return se.serialize(to_dict(obj, reuse_instances=False), **opts)


def from_gura(cls: Type, s: str, de: Type[Deserializer] = GuraDeserializer, **opts) -> T:

    return from_dict(cls, de.deserialize(s, **opts), reuse_instances=False)