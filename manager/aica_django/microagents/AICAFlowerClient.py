import numpy as np
import numpy.typing as npt
import torch  # type: ignore

from celery.utils.log import get_task_logger
from collections import OrderedDict
from flwr.client import NumPyClient  # type: ignore
from io import StringIO
from scipy.io import mmread  # type: ignore
from sklearn import model_selection  # type: ignore
from sklearn.preprocessing import label_binarize  # type: ignore
from torch.utils.data import DataLoader  # type: ignore
from tqdm import tqdm
from typing import Any, List, Dict, Optional, Tuple

from aica_django.connectors.GraphDatabase import AicaNeo4j
from aica_django.microagents.AICANet import AICANet


# Static list of suricata attacks have to be in place in order to create label binarizer for training the model
total_suricata_categories = [
    "Attempted Information Leak",
    "Detection of a Network Scan",
    "Detection of a Denial of Service Attack",
    "Targeted Malicious Activity was Detected",
    "Not Suspicious Traffic",
    "Unknown Traffic",
    "Potentially Bad Traffic",
    "Information Leak",
    "Large Scale Information Leak",
    "Attempted Denial of Service",
    "Denial of Service",
    "Attempted User Privilege Gain",
    "Unsuccessful User Privilege Gain",
    "Successful User Privilege Gain",
    "Attempted Administrator Privilege Gain",
    "Successful Administrator Privilege Gain",
    "Decode of an RPC Query",
    "Executable code was detected",
    "A suspicious string was detected",
    "A suspicious filename was detected",
    "An attempted login using a suspicious username was detected",
    "A system call was detected",
    "A TCP connection was detected",
    "A Network Trojan was detected",
    "A client was using an unusual port",
    "Detection of a non-standard protocol or event",
    "Generic Protocol Command Decode",
    "access to a potentially vulnerable web application",
    "Web Application Attack",
    "Misc activity",
    "Misc Attack",
    "Generic ICMP event",
    "Potential Corporate Privacy Violation",
    "Attempt to login by a default username and password",
    "Exploit Kit Activity Detected",
    "Device Retrieving External IP Address Detected",
    "Domain Observed Used for C2 Detected",
    "Possibly Unwanted Program Detected",
    "Successful Credential Theft Detected",
    "Possible Social Engineering Attempted",
    "Crypto Currency Mining Activity Detected",
    "Malware Command and Control Activity Detected",
]


logger = get_task_logger(__name__)


class AICAFlowerClient(NumPyClient):  # type: ignore
    def __init__(self, in_dim: int = 128, hidden_dim: int = 128) -> None:
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
        else:
            self.device = torch.device("cpu")

        self.aica_model = AICANet(
            in_dim=in_dim,
            hidden_dim=[hidden_dim, hidden_dim],
            out_dim=len(total_suricata_categories),
        ).to(device=self.device)
        self.graph_obj = AicaNeo4j()
        super().__init__()

    def get_parameters(
        self, config: Optional[Dict[str, Any]] = None
    ) -> List[npt.NDArray[np.float64]]:
        return [val.cpu().numpy() for _, val in self.aica_model.state_dict().items()]

    def set_parameters(self, parameters: List[npt.NDArray[np.float64]]) -> None:
        params_dict = zip(self.aica_model.state_dict().keys(), parameters)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        self.aica_model.load_state_dict(state_dict, strict=True)

    def fit(
        self,
        parameters: List[npt.NDArray[np.float64]],
        config: Optional[Dict[str, Any]] = None,
    ) -> tuple[List[npt.NDArray[np.float64]], int, dict[Any, Any]]:
        self.set_parameters(parameters)
        self.train(epochs=1)
        return self.get_parameters(), len(self.training_data_loader.dataset), {}

    def evaluate(
        self,
        parameters: List[npt.NDArray[np.float64]],
        config: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, int, Dict[str, float]]:
        self.set_parameters(parameters)
        loss, accuracy = self.test()
        return loss, len(self.validation_data_loader.dataset), {"accuracy": accuracy}

    def train(self, epochs: int = 10, lr: float = 0.001, verbose: bool = False) -> None:
        """Train the model on the training set."""
        criterion = torch.nn.CrossEntropyLoss()
        optimizer = torch.optim.SGD(self.aica_model.parameters(), lr=lr)
        self.aica_model.train()
        for epoch in range(epochs):
            correct = 0
            total = 0
            epoch_loss = 0.0

            for X_train, y_train in tqdm(
                self.training_data_loader, "Training", unit="batch"
            ):
                train_data, train_labels = X_train.to(self.device), y_train.to(
                    self.device
                )
                optimizer.zero_grad()
                outputs = self.aica_model(train_data)
                loss = criterion(outputs, train_labels.type(torch.FloatTensor))
                loss.backward()
                optimizer.step()

                # Metrics
                epoch_loss += loss
                total += train_labels.size(0)
                correct += (
                    (torch.max(outputs.data, 1)[1] == torch.max(train_labels, 1)[1])
                    .sum()
                    .item()
                )
            epoch_loss /= len(self.training_data_loader.dataset)
            epoch_acc = correct / total
            if verbose:
                logger.info(
                    f"Epoch {epoch+1}: train loss {epoch_loss}, accuracy {epoch_acc}"
                )

    def test(self) -> Tuple[float, float]:
        """Validate the model on the test set."""
        criterion = torch.nn.CrossEntropyLoss()
        self.aica_model.eval()
        correct = 0
        loss = 0.0
        with torch.no_grad():
            for X_batch, y_batch in tqdm(self.validation_data_loader, "Testing"):
                emb = X_batch.to(self.device)
                labels = y_batch.to(self.device)
                outputs = self.aica_model(emb)
                loss += criterion(outputs, labels.type(torch.FloatTensor)).item()
                correct += (
                    (torch.max(outputs.data, 1)[1] == torch.max(labels, 1)[1])
                    .sum()
                    .item()
                )
        accuracy = correct / len(self.validation_data_loader.dataset)
        return loss, accuracy

    def load_data(
        self,
        good_data: List[Tuple[str, str]],
        bad_data: List[Tuple[str, str]],
        batch_size: int = 32,
        labels_list: List[str] = total_suricata_categories,
        test_size: float = 0.2,
    ) -> torch.Tensor:
        # Combine lists to form single dataset of features and labels
        data_list = good_data + bad_data

        # Iterate through single list to get embeddings and labels
        embeds = []
        labels = []
        for node in data_list:
            embeds.append(mmread(StringIO(node[0])))
            labels.append(node[1])

        total_labels = label_binarize(labels, classes=labels_list)
        X_train, X_test, y_train, y_test = model_selection.train_test_split(
            np.array(embeds),
            total_labels,
            test_size=test_size,
        )

        # Create DataLoader object which loads in training and testing data for pytorch
        self.training_data_loader = DataLoader(
            list(zip(X_train.astype(np.float32).tolist(), y_train)),
            batch_size=batch_size,
        )
        self.validation_data_loader = DataLoader(
            list(zip(X_test.astype(np.float32).tolist(), y_test)),
            batch_size=batch_size,
        )
