import random

from typing import NamedTuple, List, Tuple, Dict, Any, Union

from cyst.api.environment.metadata_provider import MetadataProvider, MetadataProviderDescription
from cyst.api.environment.configuration import ActionConfiguration
from cyst.api.environment.stores import ActionStore
from cyst.api.logic.action import Action, ActionParameter, ActionParameterType, ActionParameterDomain, ActionParameterDomainType
from cyst.api.logic.metadata import Metadata, Flow, FlowDirection, Flags, TCPFlags, Protocol, Event


class ActionParametrization(NamedTuple):
    action_name: str
    action_parameters: List[ActionParameter]
    metadata: Dict[Tuple, Tuple[str, float]]


class StochasticMetadataProvider(MetadataProvider):
    def __init__(self, action_store: ActionStore, action_configuration: ActionConfiguration):
        self._action_store = action_store
        self._action_configuration = action_configuration
        self._mappings: Dict[str, ActionParametrization] = {}

    def register_action_parameters(self) -> None:

        list_mappings = []

        # aif:active_recon:host_discovery
        list_mappings.append(ActionParametrization(
            action_name="aif:active_recon:host_discovery",
            action_parameters=[
                ActionParameter(ActionParameterType.NONE, "scanning_technique",
                                self._action_configuration.create_action_parameter_domain_options("TCP SYN", [
                                    "UDP", "TCP connect", "TCP SYN", "ICMP", "FIN", "ACK", "IP", "NULL", "XMAS"
                                ]))
            ],
            metadata={
                ("UDP", ): ("alert:scan_detected", 0.2),
                ("TCP connect", ): ("alert:scan_detected", 0.3),
                ("TCP SYN", ): ("alert:scan_detected", 0.3),
                ("ICMP", ): ("alert:scan_detected", 0.4),
                ("FIN",): ("alert:scan_detected", 0.2),
                ("ACK",): ("alert:scan_detected", 0.2),
                ("IP",): ("alert:scan_detected", 0.3),
                ("NULL",): ("alert:scan_detected", 0.1),
                ("XMAS", ): ("alert:scan_detected", 1)
            }
        ))

        list_mappings.append(ActionParametrization(
            action_name="aif:active_recon:service_discovery",
            action_parameters=[
                ActionParameter(ActionParameterType.NONE, "scanning_technique",
                                self._action_configuration.create_action_parameter_domain_options("TCP SYN", [
                                    "UDP", "TCP connect", "TCP SYN", "ICMP", "FIN", "ACK", "IP", "NULL", "XMAS"
                                ]))
            ],
            metadata={
                tuple(): ("alert:scan_detected", 0.4)
            }
        ))

        list_mappings.append(ActionParametrization(
            action_name="aif:active_recon:vulnerability_discovery",
            action_parameters=[
            ],
            metadata={
                tuple(): ("alert:scan_detected", 0.1)
            }
        ))

        list_mappings.append(ActionParametrization(
            action_name="aif:active_recon:information_discovery",
            action_parameters=[
            ],
            metadata={
                tuple(): ("alert:scan_detected", 0.1)
            }
        ))

        list_mappings.append(ActionParametrization(
            action_name="aif:ensure_access:command_and_control",
            action_parameters=[
            ],
            metadata={
                tuple(): ("alert:unauthorized_access", 0.2)
            }
        ))

        list_mappings.append(ActionParametrization(
            action_name="aif:ensure_access:lateral_movement",
            action_parameters=[
            ],
            metadata={
                tuple(): ("alert:unauthorized_access", 0.1)
            }
        ))

        list_mappings.append(ActionParametrization(
            action_name="aif:disclosure:data_exfiltration",
            action_parameters=[
            ],
            metadata={
                tuple(): ("alert:data_manipulation", 0.3)
            }
        ))

        for mapping in list_mappings:
            # Register parameters to actions
            action = self._action_store.get_ref(mapping.action_name)
            action.add_parameters(*mapping.action_parameters)

            # Save it for processing
            self._mappings[mapping.action_name] = mapping

    def get_metadata(self, action: Action) -> Metadata:

        if action.id not in self._mappings:
            return Metadata()

        parametrization = self._mappings[action.id]

        if not parametrization:
            return Metadata()

        # get metadata key
        values = []
        for param in parametrization.action_parameters:
            ap = action.parameters[param.name]
            # TODO default value of action parameter should be automagically obtained if no value is present
            if ap.value:
                values.append(ap.value)
            else:
                values.append(ap.domain.default())

        # Get appropriate metadata event + probability
        try:
            event, probability = parametrization.metadata[tuple(values)]
        except KeyError:
            # Combination of values not available
            return Metadata()

        if random.random() < probability:
            return Metadata(event=event)
        else:
            return Metadata()


def create_simulated_metadata_provider(action_store: ActionStore, action_configuration: ActionConfiguration) -> StochasticMetadataProvider:
    provider = StochasticMetadataProvider(action_store, action_configuration)
    return provider


metadata_provider_description = MetadataProviderDescription(
    "aif",
    "Provider for probabilistic metadata in the Adversary-Intent Framework context",
    create_simulated_metadata_provider
)
