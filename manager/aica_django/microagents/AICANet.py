import torch  # type: ignore

import numpy as np
import numpy.typing as npt
import torch.nn as nn  # type: ignore
import torch.nn.functional as F  # type: ignore

from celery.utils.log import get_task_logger
from typing import List

logger = get_task_logger(__name__)


class AICANet(torch.nn.Module):  # type: ignore
    def __init__(self, in_dim: int, hidden_dim: List[int], out_dim: int) -> None:
        super().__init__()
        self.dense1 = nn.Linear(in_dim, hidden_dim[0])
        self.dense2 = nn.Linear(hidden_dim[0], hidden_dim[1])
        self.dense3 = nn.Linear(hidden_dim[1], out_dim)

    def forward(self, data: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        x: npt.NDArray[np.float64] = self.dense1(data)
        x = F.relu(x)
        x = self.dense2(x)
        x = F.relu(x)
        x = self.dense3(x)
        x = F.relu(x)
        return x
