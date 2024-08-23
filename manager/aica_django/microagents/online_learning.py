"""
This microagent is responsible for pulling in any external data relevant to decision-
making by the agent and loading/sending it to the knowledge base microagent during
runtime.

This should eventually include:
* World Description
* Competence
* Purpose
* Behavior
"""

import argparse
from io import StringIO

import numpy as np
from celery.utils.log import get_task_logger
from collections import OrderedDict
from connectors import GraphDatabase
from flwr.client import NumPyClient, ClientApp
from scipy.io import mmread
from sklearn import preprocessing, model_selection

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torchvision.transforms import Compose, Normalize, ToTensor
from tqdm import tqdm
import warnings

logger = get_task_logger(__name__)


# #############################################################################
# 1. Regular PyTorch pipeline: nn.Module, train, test, and DataLoader
# #############################################################################

warnings.filterwarnings("ignore", category=UserWarning)
if torch.backends.cuda.is_available():
    device = torch.device("cuda")
else:
    device = torch.device("cpu")


class AICAMLP(torch.nn.Module):
    """Model (simple MLP adapted from 'PyTorch: A 60 Minute Blitz')"""

    def __init__(self, in_dim, hidden_dim, out_dim):
        super().__init__()
        self.dense1 = nn.Linear(in_dim, hidden_dim[0])
        self.dense2 = nn.Linear(hidden_dim[0], hidden_dim[1])
        self.dense3 = nn.Linear(hidden_dim[1], out_dim)

    def forward(self, data):
        x = self.dense1(data)
        x = F.relu(x)
        x = self.dense2(x)
        x = F.relu(x)
        x = self.dense3(x)
        x = F.relu(x)
        return x


def train(model, trainloader, epochs, verbose=False):
    """Train the model on the training set."""
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.SGD(model.parameters(), lr=0.001)
    model.train()
    for epoch in range(epochs):
        correct, total, epoch_loss = 0, 0, 0.0
        for X_train, y_train in tqdm(trainloader, "Training", unit="batch"):
            train_data, train_labels = X_train.to(device), y_train.to(device)
            optimizer.zero_grad()
            outputs = model(train_data)
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
        epoch_loss /= len(trainloader.dataset)
        epoch_acc = correct / total
        if verbose:
            print(f"Epoch {epoch+1}: train loss {epoch_loss}, accuracy {epoch_acc}")


def test(model, testloader):
    """Validate the model on the test set."""
    criterion = torch.nn.CrossEntropyLoss()
    model.eval()
    correct, loss = 0, 0.0
    with torch.no_grad():
        for X_batch, y_batch in tqdm(testloader, "Testing"):
            emb = X_batch.to(device)
            labels = y_batch.to(device)
            outputs = model(emb)
            loss += criterion(outputs, labels.type(torch.FloatTensor)).item()
            correct += (
                (torch.max(outputs.data, 1)[1] == torch.max(labels, 1)[1]).sum().item()
            )
    accuracy = correct / len(testloader.dataset)
    return loss, accuracy


def load_model_params(model, model_path: str):
    """
    Pytorch model parameters will be called here!
    """
    model.load_state_dict(torch.load(model_path))
    print("Model pre-loaded!")
    return model


def load_data(batch_size=32) -> torch.Tensor:
    """
    Load cypher queries and get data from neo4j to run the model!
    """
    graph_obj = GraphDatabase.AicaNeo4j()
    bad_traff_query = "MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`) WHERE n.graph_embedding IS NOT NULL RETURN n.graph_embedding AS embedding, m.name AS category"
    non_attacks_query = "MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`) WHERE n.graph_embedding IS NOT NULL WITH COLLECT(DISTINCT n) AS all_connected_to_m MATCH (n2:`network-traffic`) WHERE NOT n2 IN all_connected_to_m RETURN n2.graph_embedding AS embedding, 'Not Attack' AS category"

    attack_data, _, _ = graph_obj.graph.execute_query(bad_traff_query)
    non_attack_data, _, _ = graph_obj.graph.execute_query(non_attacks_query)

    # Combine lists to form single dataset of features and labels
    # Iterate through single list to get embeddings and labels
    data_list = attack_data + non_attack_data
    embeds = []
    labels = []
    for node in data_list:
        embeds.append(mmread(StringIO(node[0])))
        labels.append(node[1])
    X_train, X_test, y_train, y_test = model_selection.train_test_split(np.array(embeds), labels,
    test_size=0.25, random_state=42)
    target_encoding = preprocessing.LabelBinarizer()
    train_targets = target_encoding.fit_transform(y_train)
    test_targets = target_encoding.transform(y_test)


    # Create DataLoader object which loads in training and testing data for pytorch
    trainloader = DataLoader(list(zip(np.float32(X_train), train_targets)), batch_size=batch_size)
    testloader = DataLoader(list(zip(np.float32(X_test), test_targets)), batch_size=batch_size)

    return trainloader, testloader
    

# #############################################################################
# 2. Federation of the pipeline with Flower
# #############################################################################

# Get partition id
parser = argparse.ArgumentParser(description="Flower")
parser.add_argument(
    "--partition-id",
    choices=[0, 1],
    default=0,
    type=int,
    help="Partition of the dataset divided into 2 iid partitions created artificially.",
)
partition_id = parser.parse_known_args()[0].partition_id

# Load model and data 
aica_model = AICAMLP().to(device=device)
aica_model = load_model_params(model=aica_model)
trainloader, testloader = load_data(partition_id=partition_id)


# Define Flower client
class FlowerClient(NumPyClient):
    def get_parameters(self, config):
        return [val.cpu().numpy() for _, val in aica_model.state_dict().items()]

    def set_parameters(self, parameters):
        params_dict = zip(aica_model.state_dict().keys(), parameters)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        aica_model.load_state_dict(state_dict, strict=True)

    def fit(self, parameters, config):
        self.set_parameters(parameters)
        train(aica_model, trainloader, epochs=1)
        return self.get_parameters(config={}), len(trainloader.dataset), {}

    def evaluate(self, parameters, config):
        self.set_parameters(parameters)
        loss, accuracy = test(aica_model, testloader)
        return loss, len(testloader.dataset), {"accuracy": accuracy}


def client_fn(cid: str):
    """Create and return an instance of Flower `Client`."""
    return FlowerClient().to_client()


# Flower ClientApp
app = ClientApp(
    client_fn=client_fn,
)


# Legacy mode
if __name__ == "__main__":
    from flwr.client import start_client

    start_client(
        server_address="127.0.0.1:8080",
        client=FlowerClient().to_client(),
    )
