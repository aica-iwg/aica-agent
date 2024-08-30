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
from sklearn.preprocessing import label_binarize

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torchvision.transforms import Compose, Normalize, ToTensor
from tqdm import tqdm
import warnings

logger = get_task_logger(__name__)

# Static list of suricata attacks have to be in place in order to create label binarizer for training the model!
total_suricata_categories = ['Attempted Information Leak', 'Detection of a Network Scan',  'Detection of a Denial of Service Attack', 
                'Targeted Malicious Activity was Detected','Not Suspicious Traffic', 'Unknown Traffic', 'Potentially Bad Traffic',
                'Information Leak',
'Large Scale Information Leak', 'Attempted Denial of Service',
'Denial of Service', 'Attempted User Privilege Gain',
'Unsuccessful User Privilege Gain', 'Successful User Privilege Gain',
'Attempted Administrator Privilege Gain',
'Successful Administrator Privilege Gain', 'Decode of an RPC Query',
'Executable code was detected', 'A suspicious string was detected',
'A suspicious filename was detected',
'An attempted login using a suspicious username was detected',
'A system call was detected', 'A TCP connection was detected',
'A Network Trojan was detected', 'A client was using an unusual port',
'Detection of a non-standard protocol or event',
'Generic Protocol Command Decode',
'access to a potentially vulnerable web application',
'Web Application Attack', 'Misc activity', 'Misc Attack',
'Generic ICMP event', 'Potential Corporate Privacy Violation',
'Attempt to login by a default username and password',
'Exploit Kit Activity Detected',
'Device Retrieving External IP Address Detected',
'Domain Observed Used for C2 Detected',
'Possibly Unwanted Program Detected',
'Successful Credential Theft Detected',
'Possible Social Engineering Attempted',
'Crypto Currency Mining Activity Detected',
'Malware Command and Control Activity Detected']


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


def load_model_params(model, model_path = None):
    """
    Pytorch model parameters will be called here!
    """
    if model_path != None:
        model.load_state_dict(torch.load(model_path))
        print("Model pre-loaded!")
    return model


def load_data(batch_size=32, labels_list = total_suricata_categories) -> torch.Tensor:
    """
    Load cypher queries and get data from neo4j to run the model!
    """
    graph_obj = GraphDatabase.AicaNeo4j()
    attack_data_query = "MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`) WHERE n.graph_embedding IS NOT NULL RETURN n.graph_embedding AS embedding, m.name AS category"
    non_attack_query = "MATCH (n:`network-traffic`)<-[:object]-(:`observed-data`)-[:sighting_of]->(:indicator)-[:indicates]->(m:`attack-pattern`) WHERE n.graph_embedding IS NOT NULL WITH COLLECT(DISTINCT n) AS all_connected_to_m MATCH (n2:`network-traffic`) WHERE NOT n2 IN all_connected_to_m RETURN n2.graph_embedding AS embedding, 'Not Attack' AS category"

    attack_data, _, _ = graph_obj.graph.execute_query(attack_data_query)
    non_attack_data, _, _ = graph_obj.graph.execute_query(non_attack_query)

    # Combine lists to form single dataset of features and labels
    # Iterate through single list to get embeddings and labels
    data_list = attack_data + non_attack_data
    embeds = []
    labels = []
    for node in data_list:
        embeds.append(mmread(StringIO(node[0])))
        labels.append(node[1])

    total_labels = label_binarize(labels, classes=labels_list)
    X_train, X_test, y_train, y_test = model_selection.train_test_split(np.array(embeds), total_labels,
    test_size=0.25, random_state=42)

    # Create DataLoader object which loads in training and testing data for pytorch
    trainloader = DataLoader(list(zip(np.float32(X_train), y_train)), batch_size=batch_size)
    testloader = DataLoader(list(zip(np.float32(X_test), y_test)), batch_size=batch_size)

    return trainloader, testloader
    

# #############################################################################
# 2. Federation of the pipeline with Flower
# #############################################################################

# Get partition id
parser = argparse.ArgumentParser(description="AICA")
parser.add_argument(
    "--partition-id",
    choices=[0, 1],
    default=0,
    type=int,
    help="Partition of the dataset divided into 2 iid partitions created artificially.",
)
partition_id = parser.parse_known_args()[0].partition_id

# Load model and data 
aica_model = AICAMLP(in_dim=128, hidden_dim=[128, 128], out_dim=len(total_suricata_categories)).to(device=device)
aica_model = load_model_params(model=aica_model)
trainloader, testloader = load_data()


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