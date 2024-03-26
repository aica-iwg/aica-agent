import datetime
import hashlib
import uuid

from stix2 import AttackPattern, Identity, Incident, Indicator, Note
from stix2.base import _STIXBase  # type: ignore
from typing import List

# These overwrite the default classes to create a deterministic ID where STIX doesn't otherwise provide one


def str_to_uuid(input_str: str) -> uuid:
    m = hashlib.md5(usedforsecurity=False)
    m.update(input_str.encode("utf-8"))
    return uuid.UUID(int=int(m.hexdigest(), 16), version=4)


class AICAAttackPattern(AttackPattern):
    def __init__(
        self,
        name,
        external_references=None,
        description=None,
        aliases=None,
        kill_chain_phases=None,
    ) -> None:
        super().__init__(
            id=f"attack-pattern--{str_to_uuid(name)}",
            name=name,
            external_references=external_references,
            description=description,
            aliases=aliases,
            kill_chain_phases=kill_chain_phases,
        )


class AICAIndicator(Indicator):
    def __init__(
        self,
        name: str,
        description: str = None,
        indicator_types: List[str] = None,
        pattern: str = None,
        pattern_type: str = None,
        pattern_version: str = None,
        valid_from: datetime.datetime = None,
        valid_until: datetime.datetime = None,
        kill_chain_phases: List[str] = None,
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


class AICAIdentity(Identity):
    def __init__(
        self,
        name: str,
        description: str = None,
        roles: List[str] = None,
        identity_class: str = None,
        sectors: List[str] = None,
        contact_information: str = None,
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


class AICAIncident(Incident):
    def __init__(
        self,
        name: str,
        description: str = None,
    ) -> None:
        super().__init__(
            id=f"incident--{str_to_uuid(name)}",
            name=name,
            description=description,
        )


class AICANote(Note):
    def __init__(
        self,
        abstract: str,
        object_refs: List[_STIXBase],
        content: str = None,
        authors: List[str] = None,
    ) -> None:
        super().__init__(
            id=f"note--{str_to_uuid(abstract)}",
            abstract=abstract,
            object_refs=object_refs,
            content=content,
            authors=authors,
        )
