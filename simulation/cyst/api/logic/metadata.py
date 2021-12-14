from abc import ABC, abstractmethod
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, NamedTuple, Optional
from flags import Flags
from netaddr import IPAddress


class Event(NamedTuple):
    id: str


class TCPFlags(Flags):
    S = ()
    A = ()
    R = ()
    P = ()
    U = ()
    F = ()


class Protocol(Enum):
    UDP = auto()
    TCP = auto()
    ICMP = auto()


class FlowDirection(Enum):
    REQUEST = auto()
    RESPONSE = auto()


class Flow(NamedTuple):
    id: str
    direction: FlowDirection
    packet_count: int
    duration: int
    flags: TCPFlags
    protocol: Protocol


@dataclass
class Metadata:
    src_ip: Optional[IPAddress] = None
    dst_ip: Optional[IPAddress] = None
    dst_service: Optional[str] = None
    event: Optional[str] = None
    flows: Optional[List[Flow]] = None
