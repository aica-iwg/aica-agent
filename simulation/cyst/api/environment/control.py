import uuid

from abc import ABC, abstractmethod
from enum import Enum
from typing import Tuple


class EnvironmentState(Enum):
    """
    The current state of the environment.

                          reset()                 terminate()
                         ┌────────── TERMINATED ◄───────────┐
                         │               ▲                  │
                         │    terminate()│                  │
                         ▼               │    ──pause()──►  │
    CREATED ──init()─► INIT ──run()─► RUNNING             PAUSED
                         ▲               │    ◄──run()───
                         │               │
                         │               ▼
                         └────────── FINISHED
                          reset()
    """
    CREATED = -1,
    INIT = 0,
    RUNNING = 1,
    PAUSED = 2,
    FINISHED = 3,
    TERMINATED = 4


class EnvironmentControl(ABC):
    """
    EnvironmentControl provides mechanisms to control the execution of actions within the simulation environment.

    Available to: creator
    Hidden from:  agents, models
    """

    @property
    @abstractmethod
    def state(self) -> EnvironmentState:
        """ Provides the current state of the environment. """
        pass

    @abstractmethod
    def init(self, run_id: str = str(uuid.uuid4())) -> Tuple[bool, EnvironmentState]:
        """ Initializes the environment for the first time. The environment must be in the CREATED state.
        The following invocations do nothing and silently return true.

        :param run_id: The unique id of the current run. If a non-unique id is selected, it may produced unwanted
            results when saving the data to a data store.
        :type run_id: str

        :returns A tuple indicating, whether the operation was successful and which state the environment ended in.
        :rtype Tuple[bool, EnvironmentState]
        """
        pass

    @abstractmethod
    def commit(self) -> None:
        """ Stores the information of the currently executed run into the data store. This can only be executed from
        the FINISHED or TERMINATED state.
        """
        pass

    @abstractmethod
    def reset(self, run_id: str = str(uuid.uuid4())) -> Tuple[bool, EnvironmentState]:
        """ Resets the environment for another run. Only a previously FINISHED or TERMINATED run can be reset.

        :param run_id: The unique id of the current run. If a non-unique id is selected, it may produced unwanted
            results when saving the data to a data store.
        :type run_id: str

        :returns A tuple indicating, whether the operation was successful and which state the environment ended in.
        :rtype Tuple[bool, EnvironmentState]
        """
        pass

    @abstractmethod
    def run(self) -> Tuple[bool, EnvironmentState]:
        """ Starts or resumes the message processing in the current run. If the environment is in the INIT state, it
        activates the active services. If it is in INIT or PAUSED state, it begins message processing and transitions
        into the RUNNING state.

        :returns A tuple indicating, whether the operation was successful and which state the environment ended in.
        :rtype Tuple[bool, EnvironmentState]
        """
        pass

    @abstractmethod
    def pause(self) -> Tuple[bool, EnvironmentState]:
        """ Invokes an explicit transition into the PAUSED state and temporarily halts the message processing. Can only
        be applied in the running state.

        :returns A tuple indicating, whether the operation was successful and which state the environment ended in.
        :rtype Tuple[bool, EnvironmentState]
        """
        pass

    @abstractmethod
    def terminate(self) -> Tuple[bool, EnvironmentState]:
        """ Halts the message processing and transitions the environment into the TERMINATED state. From this state
        the environment cannot be re-run.

        :returns A tuple indicating, whether the operation was successful and which state the environment ended in.
        :rtype Tuple[bool, EnvironmentState]
        """
        pass

    @abstractmethod
    def add_pause_on_request(self, id: str) -> None:
        """ Adds an explicit interrupt to message processing, whenever a service sends a request. Transitions the
        environment into the PAUSED state. Used mainly in tests to break from the run().

        :param id: A fully qualified id of a service, i.e., also containing the node id.
        """
        pass

    @abstractmethod
    def remove_pause_on_request(self, id: str) -> None:
        """ Removes an explicit interrupt to message processing, whenever a service sends a request.

        :param id: A fully qualified id of a service, i.e., also containing the node id.
        """
        pass

    @abstractmethod
    def add_pause_on_response(self, id: str) -> None:
        """ Adds an explicit interrupt to message processing, whenever a service receives a response. Transitions the
        environment into the PAUSED state. Used mainly in tests to break from the run().

        :param id: A fully qualified id of a service, i.e., also containing the node id.
        """
        pass

    @abstractmethod
    def remove_pause_on_response(self, id: str) -> None:
        """ Removes an explicit interrupt to message processing, whenever a service sends a request.

        :param id: A fully qualified id of a service, i.e., also containing the node id.
        """
        pass
