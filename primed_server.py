from typing import Any, Callable, Dict, List, Optional, Tuple
from collections import OrderedDict
import flwr as fl
from typing import List, Tuple
from flwr.server.strategy.dp_fixed_clipping import DifferentialPrivacyServerSideFixedClipping
from flwr.common import Context, Metrics, ndarrays_to_parameters
from flwr.server import ServerApp, ServerAppComponents, ServerConfig
from flwr.server.strategy import FedAvg
from flwr.common import Parameters, NDArrays, Scalar, Context
import torch
import torch.nn as nn
import torch.nn.functional as F
from io import BytesIO
from typing import cast
import numpy as np

""""
This is a server-side FL code that incorporaates initial parameters from a previous model to act as the starting point of the FL optmization
make sure you set the path of the saved model file onto the "filepath" variable
"""
filepath = '/Users/l00330924/Downloads/net_model.pth'

def get_parameters(n):
        return [val.cpu().numpy() for _, val in n.state_dict().items()]

class Net(nn.Module):
    """Model (simple CNN adapted from 'PyTorch: A 60 Minute Blitz')"""

    def __init__(self) -> None:
        super(Net, self).__init__()
        self.conv1 = nn.Conv2d(3, 6, 5)
        self.pool = nn.MaxPool2d(2, 2)
        self.conv2 = nn.Conv2d(6, 16, 5)
        self.fc1 = nn.Linear(16 * 5 * 5, 120)
        self.fc2 = nn.Linear(120, 84)
        self.fc3 = nn.Linear(84, 10)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = x.view(-1, 16 * 5 * 5)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)
    
def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
    # Multiply accuracy of each client by number of examples used
    accuracies = [num_examples * m["accuracy"] for num_examples, m in metrics]
    examples = [num_examples for num_examples, _ in metrics]
    # Aggregate and return custom metric (weighted average)
    return {"accuracy": sum(accuracies) / sum(examples)}

def main() -> None:
    clf = Net()
    PATH = filepath
    clf.load_state_dict(torch.load(PATH, map_location=torch.device('cpu')))
    parameters = fl.common.ndarrays_to_parameters(get_parameters(clf))                      # Serialize ndarrays to `Parameters`
    # Create strategy
    strategy = fl.server.strategy.FedAvg(
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=2,
        min_evaluate_clients=2,
        min_available_clients=2,
        evaluate_fn=None,
        evaluate_metrics_aggregation_fn=weighted_average,
        on_fit_config_fn=fit_config,
        initial_parameters=parameters,
    )
    dp_strategy = DifferentialPrivacyServerSideFixedClipping(
        strategy,
        noise_multiplier = 0.01,
        clipping_norm = 0.999,
        num_sampled_clients = 2.0,
    )

    # Start Flower server for 10 rounds of federated learning
    fl.server.start_server(
        server_address="127.0.0.1:8080",
        config=fl.server.ServerConfig(num_rounds=5),
        strategy=dp_strategy,
    )
def fit_config(server_round: int):
    """Return training configuration dict for each round.
    Keep batch size fixed at 32, perform two rounds of training with one local epoch,
    increase to two local epochs afterwards.
    """
    config = {
        "batch_size": 32,
        "local_epochs": 5,
        "learning_rate":0.01,
    }
    return config

#def get_on_fit_config_fn() -> Callable[[int], Dict[str, str]]:
#    """Return a function which returns training configurations."""
#
#    def fit_config(server_round: int) -> Dict[str, str]:
#        """Return a configuration with static batch size and (local) epochs."""
#        config = {
#            "learning_rate": str(0.001),
#            "batch_size": str(32),
#        }
#        return config
#
#    return fit_config

if __name__ == "__main__":
    main()

