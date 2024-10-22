import numpy as np
import numpy.typing as npt
import torch  # type: ignore

from celery.utils.log import get_task_logger
from collections import OrderedDict
from flwr.client import NumPyClient  # type: ignore
from io import StringIO
from scipy.io import mmread  # type: ignore
from sklearn import model_selection  # type: ignore
from sklearn.preprocessing import LabelEncoder, label_binarize  # type: ignore
from torch.utils.data import DataLoader  # type: ignore
from tqdm import tqdm
from typing import Any, List, Dict, Optional, Sized, Tuple

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


class AICADataset(torch.utils.data.Dataset[Any], Sized):  # type: ignore
    def __init__(
        self, data_list: List[Tuple[npt.NDArray[np.float32], npt.NDArray[Any]]]
    ) -> None:
        super().__init__()
        self.data_list = data_list

    def __len__(self) -> int:
        return len(self.data_list)

    def __getitem__(self, idx: int) -> Tuple[npt.NDArray[Any], npt.NDArray[Any]]:
        return self.data_list[idx]


class AICAFlowerClient(NumPyClient):  # type: ignore
    def __init__(self, in_dim: int = 128, hidden_dim: int = 128) -> None:
        super().__init__()

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
        self.train(epochs=50, verbose=True)
        return self.get_parameters(), len(self.training_dataset), {}

    def evaluate(
        self,
        parameters: List[npt.NDArray[np.float64]],
        config: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, int, Dict[str, float]]:
        self.set_parameters(parameters)
        loss, accuracy = self.test()
        return loss, len(self.validation_dataset), {"accuracy": accuracy}

    def train(self, epochs: int = 10, lr: float = 0.001, verbose: bool = False) -> None:
        if not self.training_data_loader:
            logger.warning("No training data, cannot train")
            return

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
                loss = criterion(outputs, train_labels)
                loss.backward()
                optimizer.step()

                # Metrics
                epoch_loss += loss
                total += train_labels.size(0)
                correct += (torch.max(outputs.data, 1)[1] == train_labels).sum().item()

            epoch_loss /= len(self.training_dataset)
            epoch_acc = correct / total
            if verbose:
                logger.info(
                    f"Epoch {epoch+1}: train loss {epoch_loss}, accuracy {epoch_acc}"
                )

    def test(self) -> Tuple[float, float]:
        if not self.validation_data_loader:
            logger.warning("No validation data, cannot test")
            return np.nan, np.nan

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
                loss += criterion(outputs, labels)
                correct += (torch.max(outputs.data, 1)[1] == labels).sum().item()
        accuracy = correct / len(self.validation_dataset)
        return loss, accuracy

    def load_data(
        self,
        good_data: List[Tuple[str, str]],
        bad_data: List[Tuple[str, str]],
        batch_size: int = 32,
        suricata_labels_list: List[str] = total_suricata_categories,
        test_size: float = 0.2,
    ) -> None:
        # Combine lists to form single dataset of features and labels
        data_list = good_data + bad_data

        if len(data_list) == 0:
            logger.warning("Returning without any data to train on")
            self.training_data_loader = None
            self.validation_data_loader = None
            raise ValueError("No training data")

        # Iterate through single list to get embeddings and labels
        embeds = []
        node_labels = []
        for node in data_list:
            embeds.append(mmread(StringIO(node[0])))
            node_labels.append(node[1])

        total_labels = label_binarize(node_labels, classes=suricata_labels_list)
        aica_labels = np.argmax(total_labels, axis=1)

        embed_arr = np.array(embeds)
        embed_arr = np.reshape(embed_arr, (len(embed_arr), embed_arr.shape[2]))

        X_train, X_test, y_train, y_test = model_selection.train_test_split(
            embed_arr,
            aica_labels,
            test_size=test_size,
        )

        self.training_dataset = AICADataset(
            list(zip(X_train.astype(np.float32), y_train))
        )
        self.training_data_loader = DataLoader(
            self.training_dataset,
            batch_size=batch_size,
        )
        self.validation_dataset = AICADataset(
            list(zip(X_test.astype(np.float32), y_test))
        )
        self.validation_data_loader = DataLoader(
            self.validation_dataset,
            batch_size=batch_size,
        )
