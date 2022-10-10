import os

from neomodel import (  # type: ignore
    config,
    StructuredNode,
    StringProperty,
    IntegerProperty,
    RelationshipTo,
)

config.DATABASE_URL = os.environ["NEO4J_BOLT_URL"]


class IPv4Address(StructuredNode):
    name = StringProperty()
    value = StringProperty()


class AttackSignatureCategory(StructuredNode):
    name = StringProperty()


class AttackSignature(StructuredNode):
    name = StringProperty()
    gid = IntegerProperty(default=0)
    signature_id = IntegerProperty(default=0)
    rev = StringProperty()
    signature = StringProperty()
    severity = StringProperty()
    signature_category = RelationshipTo(AttackSignatureCategory, "member-of")


class Alert(StructuredNode):
    time_tripped = IntegerProperty(default=0)
    flow_id = IntegerProperty(default=0)
    attack_signature = RelationshipTo(AttackSignature, "is-type")


class Host(StructuredNode):
    id = StringProperty()
    last_seen = IntegerProperty(default=0)


class NetworkTraffic(StructuredNode):
    name = StringProperty()
    in_packets = IntegerProperty(default=0)
    in_octets = IntegerProperty(default=0)
    start = IntegerProperty(default=0)
    end = IntegerProperty(default=0)
    flags = StringProperty()
    tos = StringProperty()
    source = StringProperty()
