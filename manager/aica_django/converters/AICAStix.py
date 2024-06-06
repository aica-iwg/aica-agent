import hashlib
import json
import uuid

from datetime import datetime
from stix2 import (  # type:ignore
    Artifact,
    AttackPattern,
    Identity,
    Incident,
    Indicator,
    IPv4Address,
    IPv6Address,
    Location,
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
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
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
        protocols: Union[str, list[str]],
        src_ref: Union[IPv4Address, IPv6Address],
        dst_ref: Union[IPv4Address, IPv6Address],
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
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


class AICALocation(Location):  # type: ignore
    def __init__(
        self,
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        administrative_area: Optional[str] = None,
        city: Optional[str] = None,
        confidence: Optional[int] = None,
        country: Optional[str] = None,
        created_by_ref: Optional[str] = None,
        description: Optional[str] = None,
        extensions: Optional[List[Dict[str, Any]]] = None,
        external_references: Optional[List[str]] = None,
        granular_markings: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        lang: Optional[str] = None,
        name: Optional[str] = None,
        object_marking_refs: Optional[List[str]] = None,
        postal_code: Optional[str] = None,
        region: Optional[str] = None,
        revoked: Optional[bool] = None,
        street_address: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        precision: Optional[float] = None,
    ):
        id_dict = dict(
            administrative_area=administrative_area,
            city=city,
            confidence=confidence,
            country=country,
            description=description,
            extensions=extensions,
            external_references=external_references,
            granular_markings=granular_markings,
            labels=labels,
            lang=lang,
            name=name,
            postal_code=postal_code,
            region=region,
            revoked=revoked,
            street_address=street_address,
            latitude=latitude,
            longitude=longitude,
            precision=precision,
        )

        super().__init__(
            id=f"location--{str_to_uuid(json.dumps(id_dict))}",
            created=created,
            modified=modified,
            administrative_area=administrative_area,
            city=city,
            confidence=confidence,
            country=country,
            created_by_ref=created_by_ref,
            description=description,
            extensions=extensions,
            external_references=external_references,
            granular_markings=granular_markings,
            labels=labels,
            lang=lang,
            name=name,
            object_marking_refs=object_marking_refs,
            postal_code=postal_code,
            region=region,
            revoked=revoked,
            street_address=street_address,
            latitude=latitude,
            longitude=longitude,
            precision=precision,
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
