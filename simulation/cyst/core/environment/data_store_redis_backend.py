from typing import Any, Type

from rejson import Client, Path

from cyst.core.environment.data_store_backend import DataStoreBackend


class DataStoreRedisBackend(DataStoreBackend):

    def __init__(self, host: str, port: int) -> None:
        self._rj = Client(host=host, port=port, decode_responses=True)

    def set(self, run_id: str, item: Any, item_type: Type, time: int = 0) -> None:
        pass

    def get(self, run_id: str, item: Any, item_type: Type) -> Any:
        pass

    def update(self, run_id: str, item: Any, item_type: Type) -> None:
        pass

    def remove(self, run_id: str, item: Any, item_type: Type) -> None:
        pass

    def clear(self, run_id: str) -> None:
        pass

    def commit(self, run_id: str) -> None:
        pass
