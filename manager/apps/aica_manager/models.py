import os

from neomodel import (  # type: ignore
    config,
    install_all_labels,
    BooleanProperty,
    DateTimeProperty,
    StringProperty,
    IntegerProperty,
    RelationshipFrom,
    RelationshipTo,
)
from neomodel.contrib import SemiStructuredNode  # type: ignore

config.DATABASE_URL = os.environ["NEO4J_BOLT_URL"]
config.FORCE_TIMEZONE = True


class IPv4Address(SemiStructuredNode):
    id = StringProperty(required=True)
    address = StringProperty(required=True)
    class_a = StringProperty()
    class_b = StringProperty()
    class_c = StringProperty()
    is_private = BooleanProperty()
    loopback = BooleanProperty()
    multicast = BooleanProperty()
    reserved = BooleanProperty()


class AttackSignatureCategory(SemiStructuredNode):
    id = StringProperty(required=True)
    category = StringProperty(required=True)


class AttackSignature(SemiStructuredNode):
    id = StringProperty(required=True)
    gid = IntegerProperty(required=True)
    signature_id = IntegerProperty(required=True)
    rev = IntegerProperty(required=True)
    severity = IntegerProperty(required=True)
    signature = StringProperty(required=True)
    signature_category = RelationshipTo("AttackSignatureCategory", "MEMBER_OF")


class Alert(SemiStructuredNode):
    time_tripped = DateTimeProperty(required=True)
    attack_signature = RelationshipTo("AttackSignature", "IS_TYPE")
    triggered_by = RelationshipTo("NetworkTraffic", "TRIGGERED_BY")


class Host(SemiStructuredNode):
    id = StringProperty(required=True)
    last_seen = DateTimeProperty(required=True)
    ipv4_address = RelationshipTo("IPv4Address", "HAS_ADDRESS")

    # Associated Alerts
    def alerts(self, since: int = 86400):
        ip_strings = [str(x.address) for x in self.ipv4_address.all()]
        all_results = []
        for ip in ip_strings:
            results, columns = self.cypher(
                "MATCH (h:Host)-[:`HAS_ADDRESS`]->"
                "(:IPv4Address)-[:`HAS_PORT`]->"
                "(:NetworkEndpoint)-[:`COMMUNICATES_TO`]->"
                "(:NetworkTraffic)<-[:`TRIGGERED_BY`]-"
                "(a:Alert) "
                f"WHERE a.time_tripped >= (dateTime().epochMillis / 1000) - {since} AND h.id = '{ip}' "
                "RETURN a"
            )
            all_results.extend(results)

        return [self.inflate(row[0]) for row in all_results]

    def non_suspicious_source_flows(self, since: int = 86400) -> list:
        ip_strings = [str(x.address) for x in self.ipv4_address.all()]
        all_results = []
        for ip in ip_strings:
            results, columns = self.cypher(
                "MATCH (h:Host)-[:`HAS_ADDRESS`]->"
                "(:IPv4Address)-[:`HAS_PORT`]->"
                "(:NetworkEndpoint)-[:`COMMUNICATES_TO`]->"
                "(n:NetworkTraffic)"
                "WHERE EXISTS {MATCH (:Alert)-[:`TRIGGERED_BY`]->(n:NetworkTraffic)} AND "
                f"n.start >= (dateTime().epochMillis / 1000) - {since} "
                f"AND h.id = '{ip}' "
                "RETURN n"
            )
            all_results.extend(results)

        return all_results

    def suspicious_source_flows(self, since: int = 86400) -> list:
        ip_strings = [str(x.address) for x in self.ipv4_address.all()]
        all_results = []
        for ip in ip_strings:
            results, columns = self.cypher(
                "MATCH (h:Host)-[:`HAS_ADDRESS`]->"
                "(:IPv4Address)-[:`HAS_PORT`]->"
                "(:NetworkEndpoint)-[:`COMMUNICATES_TO`]->"
                "(n:NetworkTraffic)"
                "WHERE EXISTS {MATCH (:Alert)-[:`TRIGGERED_BY`]->(n:NetworkTraffic)} AND "
                f"n.start >= (dateTime().epochMillis / 1000) - {since} "
                f"AND h.id = '{ip}' "
                "RETURN n"
            )
            all_results.extend(results)

        return all_results

    # Proportion of Suspicious to Non-Suspicious Traffic (Source)
    def suspicious_source_ratio(self, since: int = 86400) -> float:
        non_suspicious_count = len(self.non_suspicious_source_flows(since=since))
        suspicious_count = len(self.suspicious_source_flows(since=since))

        try:
            ratio = float(suspicious_count) / (non_suspicious_count + suspicious_count)
        except ZeroDivisionError:
            ratio = 0

        return ratio

    def non_suspicious_destination_flows(self, since: int = 86400) -> list:
        ip_strings = [str(x.address) for x in self.ipv4_address.all()]
        all_results = []
        for ip in ip_strings:
            results, columns = self.cypher(
                "MATCH (h:Host)-[:`HAS_ADDRESS`]->"
                "(:IPv4Address)-[:`HAS_PORT`]->"
                "(:NetworkEndpoint)<-[:`COMMUNICATES_TO`]-"
                "(n:NetworkTraffic)"
                "WHERE EXISTS {MATCH (:Alert)-[:`TRIGGERED_BY`]->(n:NetworkTraffic)} AND "
                f"n.start >= (dateTime().epochMillis / 1000) - {since} "
                f"AND h.id = '{ip}' "
                "RETURN n"
            )
            all_results.extend(results)

        return all_results

    def suspicious_destination_flows(self, since: int = 86400) -> list:
        ip_strings = [str(x.address) for x in self.ipv4_address.all()]
        all_results = []
        for ip in ip_strings:
            results, columns = self.cypher(
                "MATCH (h:Host)-[:`HAS_ADDRESS`]->"
                "(:IPv4Address)-[:`HAS_PORT`]->"
                "(:NetworkEndpoint)<-[:`COMMUNICATES_TO`]-"
                "(n:NetworkTraffic)"
                "WHERE EXISTS {MATCH (:Alert)-[:`TRIGGERED_BY`]->(n:NetworkTraffic)} AND "
                f"n.start >= (dateTime().epochMillis / 1000) - {since} "
                f"AND h.id = '{ip}' "
                "RETURN n"
            )
            all_results.extend(results)

        return all_results

    # Proportion of Suspicious to Non-Suspicious Traffic (Destination)
    def suspicious_destination_ratio(self, since: int = 86400) -> float:
        non_suspicious_count = len(self.non_suspicious_destination_flows(since=since))
        suspicious_count = len(self.suspicious_destination_flows(since=since))

        try:
            ratio = float(suspicious_count) / (non_suspicious_count + suspicious_count)
        except ZeroDivisionError:
            ratio = 0

        return ratio


class NetworkEndpoint(SemiStructuredNode):
    id = StringProperty(required=True)
    protocol = IntegerProperty(required=True)
    port = IntegerProperty(required=True)
    ip_address = StringProperty(required=True)
    endpoint = StringProperty(required=True)


class NetworkTraffic(SemiStructuredNode):
    id = StringProperty(required=True)
    in_packets = IntegerProperty(required=True)
    in_octets = IntegerProperty(required=True)
    start = DateTimeProperty(required=True)
    end = DateTimeProperty(default=0)
    flags = IntegerProperty(required=True)
    tos = IntegerProperty(required=True)
    communicates_to = RelationshipTo("NetworkEndpoint", "COMMUNICATES_TO")
    communicates_from = RelationshipFrom("NetworkEndpoint", "COMMUNICATES_TO")


install_all_labels()
