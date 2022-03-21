import uuid

from typing import Optional

from cyst.api.logic.data import Data


class DataImpl(Data):
    def __init__(self, id: Optional[uuid.UUID], owner: str, description: str = ""):
        if id:
            self._id = id
        else:
            self._id = uuid.uuid4()
        self._owner = owner
        self._description = description

    @property
    def id(self):
        return self._id

    @property
    def owner(self):
        return self._owner

    @property
    def description(self):
        return self._description