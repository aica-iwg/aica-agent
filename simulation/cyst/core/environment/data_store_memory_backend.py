from typing import Any, Type

from cyst.core.environment.data_store_backend import DataStoreBackend, append_only_data, to_dict


class DataStoreMemoryBackend(DataStoreBackend):

    def __init__(self) -> None:
        self._store = {}

    def set(self, run_id: str, item: Any, item_type: Type, time: int = 0) -> None:
        if run_id not in self._store:
            self._store[run_id] = {}

        item_name = item_type.__name__

        item_dict = to_dict(item)
        item_dict["timestamp"] = time

        if item_type in append_only_data:
            if item_name not in self._store[run_id]:
                self._store[run_id][item_name] = []
            self._store[run_id][item_name].append(item_dict)
        else:
            if item_name in self._store[run_id]:
                raise RuntimeError("Object with name {} already in the data store. Use update if you want to overwrite it".format(item_name))
            self._store[run_id][item_name] = item_dict

    def get(self, run_id: str, item: Any, item_type: Type) -> Any:
        if run_id not in self._store:
            return None

        item_name = type(item).__name__
        if item_name not in self._store[run_id]:
            return None
        else:
            return self._store[run_id][item_name]

    def update(self, run_id: str, item: Any, item_type: Type) -> None:
        if run_id not in self._store:
            raise RuntimeError("Trying to update item in non-existent simulation run")
        
        if item_type in append_only_data:
            raise RuntimeError("Cannot update append-only item.")

        item_name = item_type.__name__
        if item_name not in self._store[run_id]:
            raise RuntimeError("Can't update object with name {} - not in the data store.".format(item_name))

        self._store[run_id][item_name] = to_dict(item)

    def remove(self, run_id: str, item: Any, item_type: Type) -> None:
        if run_id not in self._store:
            raise RuntimeError("Trying to remove item from non-existent simulation run")

        item_name = type(item).__name__
        if item_name not in self._store[run_id]:
            return None

        del self._store[run_id][item_name]

    def clear(self, run_id: str) -> None:
        if run_id not in self._store:
            raise RuntimeError("Cannot clear non-existent run with ID: {}".format(run_id))

        del self._store[run_id]

    def commit(self, run_id: str) -> None:
        # For in-memory store, commit is NoOp
        return
