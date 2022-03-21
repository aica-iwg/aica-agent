from dataclasses import field
from uuid import uuid4


def get_str_uuid() -> str:
    return str(uuid4())


class ConfigItem:
    id: str = field(default_factory=get_str_uuid)
