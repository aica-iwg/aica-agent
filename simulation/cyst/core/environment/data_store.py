from enum import Enum, auto
from typing import Dict, Any, Union, Optional, List, Tuple, Type, Set

from cyst.core.environment.data_store_backend import DataStoreBackend
from cyst.core.environment.data_store_redis_backend import DataStoreRedisBackend
from cyst.core.environment.data_store_memory_backend import DataStoreMemoryBackend

# The data store is quite universal, but its main use-cases are configuration retrieval, log storage and simulation
# artifacts storage


class DataStore:

    def __init__(self, backend_type: str, backend_params: Dict[str, str]) -> None:
        self._backend_type = backend_type.lower()

        self._no_data_store = False
        if self._backend_type == "none":
            self._no_data_store = True
            return

        fn = getattr(self, "configure_" + self._backend_type, self.configure_default)
        self._backend: DataStoreBackend = fn(backend_params)

    def configure_default(self) -> None:
        raise RuntimeError("Could not find configuration function for backend " + self._backend_type)

    @staticmethod
    def configure_redis(self, host: str, port: int) -> DataStoreBackend:
        backend = DataStoreRedisBackend(host, port)
        if not backend:
            raise RuntimeError("Could not connect client")
        return backend

    @staticmethod
    def configure_memory(self) -> DataStoreBackend:
        return DataStoreMemoryBackend()

    def set(self, run_id: str, item: Any, item_type: Type, time: int = 0) -> None:
        if self._no_data_store:
            return

        if not self._backend:
            raise RuntimeError("Data store backend not configured")

        if not isinstance(item, item_type):
            raise RuntimeError("Provided data type {} is not an instance of type {}".format(type(item), item_type))

        self._backend.set(run_id, item, item_type, time)

    def get(self, run_id: str, item: Any, item_type: Type) -> Any:
        if self._no_data_store:
            return None

        if not self._backend:
            raise RuntimeError("Data store backend not configured")

        return self._backend.get(run_id, item, item_type)

    def update(self, run_id: str, item: Any, item_type: Type) -> None:
        if self._no_data_store:
            return

        if not self._backend:
            raise RuntimeError("Data store backend not configured")

        if not isinstance(item, item_type):
            raise RuntimeError("Provided data type {} is not an instance of type {}".format(type(item), item_type))

        self._backend.update(run_id, item, item_type)

    def remove(self, run_id: str, item: Any, item_type: Type) -> None:
        if self._no_data_store:
            return

        if not self._backend:
            raise RuntimeError("Data store backend not configured")

        self._backend.remove(run_id, item, item_type)

    def clear(self, run_id: str) -> None:
        if self._no_data_store:
            return

        if not self._backend:
            raise RuntimeError("Data store backend not configured")

        self._backend.clear(run_id)

    def commit(self, run_id: str) -> None:
        if self._no_data_store:
            return

        if not self._backend:
            raise RuntimeError("Data store backend not configured")

        self._backend.commit(run_id)