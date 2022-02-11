from abc import ABC, abstractmethod


class Statistics:
    """
    Statistics class tracks various statistical information about simulation runs.
    """

    @abstractmethod
    def run_id(self) -> str:
        """
        Get the ID of the current run

        :returns Run ID
        :rtype str
        """
        pass

    @abstractmethod
    def configuration_id(self) -> str:
        """
        Get the ID of the configuration that is stored in the data store and that was used for the current run.

        :returns Configuration ID
        :rtype str
        """
        pass

    @abstractmethod
    def start_time_real(self) -> float:
        """
        Get the wall clock time when the current run started. The time is in the python time() format.

        :returns Epoch of the run start.
        :rtype float
        """
        pass

    @abstractmethod
    def end_time_real(self) -> float:
        """
        Get the wall clock time when the current run was commited. The time is in the python time() format.

        :returns Epoch of the run end.
        :rtype float
        """
        pass

    @abstractmethod
    def end_time_virtual(self) -> int:
        """
        Get the virtual time of the current run, i.e., the number of ticks. As the run always starts at 0, this function
        represents also the run duration.

        :returns Virtual run duration.
        :rtype int
        """
        pass
