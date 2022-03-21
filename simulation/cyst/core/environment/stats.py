import uuid

from dataclasses import dataclass, field

from cyst.api.environment.stats import Statistics


@dataclass
class StatisticsImpl(Statistics):
    run_id: str = field(default_factory=uuid.uuid4)
    configuration_id: str = ""
    start_time_real: float = 0.0
    end_time_real: float = 0.0
    end_time_virtual: int = 0
