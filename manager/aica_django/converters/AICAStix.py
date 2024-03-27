import datetime
import hashlib
import uuid

from stix2 import AttackPattern, Identity, Incident, Indicator, Note  # type:ignore
from stix2.base import _STIXBase  # type: ignore
from typing import Dict, List, Optional

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
