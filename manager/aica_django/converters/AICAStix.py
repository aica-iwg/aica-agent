import datetime
import hashlib
import json
import uuid

from stix2 import (  # type:ignore
    Artifact,
    AttackPattern,
    Identity,
    Incident,
    Indicator,
    IPv4Address,
    IPv6Address,
    NetworkTraffic,
    Note,
)
from stix2.base import _STIXBase  # type: ignore
from typing import Any, Dict, List, Optional, Union

# These overwrite the default classes to create a deterministic ID where STIX doesn't otherwise provide one


def str_to_uuid(input_str: str) -> uuid.UUID:
    m = hashlib.md5(usedforsecurity=False)
    m.update(input_str.encode("utf-8"))
    return uuid.UUID(int=int(m.hexdigest(), 16), version=4)


class AICAAttackPattern(AttackPattern):  # type: ignore
    def __init__(
        self,
        name: str,
        external_references: Optional[List[Dict[str, str]]] = None,
        description: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        kill_chain_phases: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            id=f"attack-pattern--{str_to_uuid(name)}",
            name=name,
            external_references=external_references,
            description=description,
            aliases=aliases,
            kill_chain_phases=kill_chain_phases,
        )


class AICAIndicator(Indicator):  # type: ignore
    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        indicator_types: Optional[List[str]] = None,
        pattern: Optional[str] = None,
        pattern_type: Optional[str] = None,
        pattern_version: Optional[str] = None,
        valid_from: Optional[datetime.datetime] = None,
        valid_until: Optional[datetime.datetime] = None,
        kill_chain_phases: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            id=f"indicator--{str_to_uuid(name)}",
            name=name,
            description=description,
            indicator_types=indicator_types,
            pattern=pattern,
            pattern_type=pattern_type,
            pattern_version=pattern_version,
            valid_from=valid_from,
            valid_until=valid_until,
            kill_chain_phases=kill_chain_phases,
        )


class AICAIdentity(Identity):  # type: ignore
    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        roles: Optional[List[str]] = None,
        identity_class: Optional[str] = None,
        sectors: Optional[List[str]] = None,
        contact_information: Optional[str] = None,
    ) -> None:
        super().__init__(
            id=f"identity--{str_to_uuid(name)}",
            name=name,
            description=description,
            roles=roles,
            identity_class=identity_class,
            sectors=sectors,
            contact_information=contact_information,
        )


class AICAIncident(Incident):  # type: ignore
    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
    ) -> None:
        super().__init__(
            id=f"incident--{str_to_uuid(name)}",
            name=name,
            description=description,
        )


class AICANetworkTraffic(NetworkTraffic):  # type: ignore
    def __init__(
        self,
        protocols: str,
        src_ref: Union[IPv4Address, IPv6Address],
        dst_ref: Union[IPv4Address, IPv6Address],
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        start: Optional[datetime.datetime] = None,
        end: Optional[datetime.datetime] = None,
        is_active: Optional[bool] = None,
        src_byte_count: Optional[int] = None,
        dst_byte_count: Optional[int] = None,
        src_packets: Optional[int] = None,
        dst_packets: Optional[int] = None,
        ipfix: Optional[Dict[str, Any]] = None,
        src_payload_ref: Optional[Artifact] = None,
        dst_payload_ref: Optional[Artifact] = None,
        encapsulates_refs: Optional[
            List[Union["AICANetworkTraffic", NetworkTraffic]]
        ] = None,
        encapsulated_by_ref: Optional[
            Union["AICANetworkTraffic", NetworkTraffic]
        ] = None,
        extensions: Optional[Dict[str, Any]] = None,
        custom_properties: Optional[Dict[str, str]] = {},
    ) -> None:
        id_dict = {
            "protocols": protocols,
            "src": src_ref["value"],
            "dst": dst_ref["value"],
            "dst_port": dst_port,
            "extensions": str(extensions),
        }

        super().__init__(
            id=f"network-traffic--{str_to_uuid(json.dumps(id_dict))}",
            protocols=protocols,
            src_ref=src_ref,
            dst_ref=dst_ref,
            src_port=src_port,
            dst_port=dst_port,
            start=start,
            end=end,
            is_active=is_active,
            src_byte_count=src_byte_count,
            dst_byte_count=dst_byte_count,
            src_packets=src_packets,
            dst_packets=dst_packets,
            ipfix=ipfix,
            src_payload_ref=src_payload_ref,
            dst_payload_ref=dst_payload_ref,
            encapsulates_refs=encapsulates_refs,
            encapsulated_by_ref=encapsulated_by_ref,
            extensions=extensions,
            custom_properties=custom_properties,
        )


class AICANote(Note):  # type: ignore
    def __init__(
        self,
        abstract: str,
        object_refs: List[_STIXBase],
        content: Optional[str] = None,
        authors: Optional[List[str]] = None,
    ) -> None:
        super().__init__(
            id=f"note--{str_to_uuid(abstract)}",
            abstract=abstract,
            object_refs=object_refs,
            content=content,
            authors=authors,
        )
