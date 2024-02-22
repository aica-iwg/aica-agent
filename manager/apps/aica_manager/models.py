"""
This module defines the models for Django data objects

Classes:
    Alert: Any type of escalated event
    AttackSignature: Types of attacks that an alert might fall into
    AttackSignatureCategory: Broader buckets of attack signatures
    Host: A physical/virtual system, potentially with multiple addresses
    IPv4Address: The IPv4 address corresponding to a host, potentially with listening ports (NetworkEndpoints)
    NetworkEndpoint: A listening or transmitting NetworkPort tied to a specific address
    NetworkTraffic: A record of a transmission over the network
Functions: modules(request), overview(request)
"""

import logging
import os

from neomodel import (  # type: ignore
    config,
    install_all_labels,
)
from neomodel.core import NodeBase  # type: ignore
from neomodel.contrib import SemiStructuredNode  # type: ignore

config.DATABASE_URL = os.environ["N4J_BOLT_URI"]
config.FORCE_TIMEZONE = True


install_all_labels()
