import json
import pandas as pd
import requests

from collections import defaultdict
from io import StringIO
from stix2 import Note, Relationship, Software  # type: ignore
from typing import Optional

from aica_django.converters.AICAStix import AICAAttackPattern
from aica_django.connectors.GraphDatabase import AicaNeo4j
from aica_django.converters.Knowledge import fake_note_root, knowledge_to_neo


graph = AicaNeo4j()

top_10_port_note = Note(
    id="note--f3cd780d-9f32-4211-b26c-42118dbbe207",
    abstract="top_10_port",
    content="top_10_port",
    object_refs=[fake_note_root],
)
top_100_port_note = Note(
    id="note--2adf3880-1a5f-4b1c-8c88-c9722238dcf0",
    abstract="top_100_port",
    content="top_100_port",
    object_refs=[fake_note_root],
)
top_1000_port_note = Note(
    id="note--40d34e90-9a9b-4350-97c6-01d64824a081",
    abstract="top_1000_port",
    content="top_1000_port",
    object_refs=[fake_note_root],
)


def create_malware_categories(import_file: Optional[str] = None) -> None:
    """
    Load a static list of ClamAV malware categories into the graph.

    @return: True once complete.
    @rtype: bool
    """

    if import_file:
        graph.merge_json_data(import_file)
    else:
        # From: https://docs.clamav.net/manual/Signatures/SignatureNames.html
        clamav_categories = [
            "Adware",
            "Backdoor",
            "Coinminer",
            "Countermeasure",
            "Downloader",
            "Dropper",
            "Exploit",
            "File",
            "Filetype",
            "Infostealer",
            "Ircbot",
            "Joke",
            "Keylogger",
            "Loader",
            "Macro",
            "Malware",
            "Packed",
            "Packer",
            "Phishing",
            "Proxy",
            "Ransomware",
            "Revoked",
            "Rootkit",
            "Spyware",
            "Test",
        ]

        malware_categories = []
        for category in clamav_categories:
            attack_pattern_name = f"clamav:{category}"
            malware_signature = AICAAttackPattern(name=attack_pattern_name)
            malware_categories.append(malware_signature)

        knowledge_to_neo(malware_categories)


port_root = Software(
    id="software--e136328d-3962-4af7-b9e5-6306fcc8d555", name="Generic Port Usage Info"
)


def create_port_info(import_file: Optional[str] = None) -> None:
    """
    Load Nmap's list (from web) of port/service info into the graph.

    @return: True once complete.
    @rtype: bool
    """
    if import_file:
        graph.merge_json_data(import_file)
    else:
        nmap_services_url = (
            "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
        )

        resp = requests.get(nmap_services_url)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise requests.exceptions.HTTPError("Couldn't fetch nmap services data.")
        nmap_file = StringIO(resp.text)
        nmap_df = pd.read_csv(
            nmap_file,
            sep="\t",
            comment="#",
            header=None,
            names=["service", "port", "frequency", "comment"],
            index_col=False,
        )
        nmap_df = nmap_df[nmap_df["service"] != "unknown"]

        # We want all parts of service, except the last part in the case of hyphenated
        nmap_df["software"] = nmap_df["service"].apply(
            lambda x: "-".join(
                x.split("-")[
                    : (
                        len(x.split("-")) - 1
                        if len(x.split("-")) > 1
                        else len(x.split("-"))
                    )
                ]
            )
        )

        nmap_df[["port_number", "protocol"]] = nmap_df["port"].str.split(
            "/", expand=True
        )
        nmap_df.drop(columns=["comment", "port"], axis=1, inplace=True)

        # For performance reasons (startup is slow creating these)
        nmap_df = nmap_df[nmap_df["frequency"] > 0]

        nmap_df["rank"] = nmap_df["frequency"].rank(ascending=False)

        port_objects = [
            port_root,
            top_10_port_note,
            top_100_port_note,
            top_1000_port_note,
        ]

        port_software_map = defaultdict(list)

        for _, row in nmap_df.iterrows():
            port_object = Note(
                abstract=f"{row['port_number']}/{row['protocol']}",
                content=json.dumps(
                    {
                        "port": row["port_number"],
                        "protocol": row["protocol"],
                        "service": row["service"],
                        "frequency": row["frequency"],
                        "rank": row["rank"],
                    }
                ),
                object_refs=[port_root.id],
            )
            port_objects.append(port_object)

            if row["rank"] <= 10:
                port_objects.append(
                    Relationship(top_10_port_note, "object", port_object)
                )
            if row["rank"] <= 100:
                port_objects.append(
                    Relationship(top_100_port_note, "object", port_object)
                )
            if row["rank"] <= 1000:
                port_objects.append(
                    Relationship(top_1000_port_note, "object", port_object)
                )

            port_software_map[row["software"]].append(port_object)

        for software, port_notes in port_software_map.items():
            software_obj = Software(name=software)
            port_objects.append(software_obj)
            for port_note in port_notes:
                port_rel = Relationship(
                    relationship_type="object",
                    source_ref=port_note,
                    target_ref=software_obj,
                )
                port_objects.append(port_rel)

        knowledge_to_neo(port_objects)


def create_suricata_categories(import_file: Optional[str] = None) -> None:
    """
    Load Suricata's list (from web) of alert categories into the graph.

    @return: True once complete.
    @rtype: bool
    """
    if import_file:
        graph.merge_json_data(import_file)
    else:
        suricata_classes_url = "https://rules.emergingthreats.net/open/suricata-5.0/rules/classification.config"

        resp = requests.get(suricata_classes_url)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise requests.exceptions.HTTPError("Couldn't fetch suricata class data.")
        suricata_file = StringIO(resp.text.replace("config classification: ", ""))
        suricata_df = pd.read_csv(
            suricata_file,
            sep=",",
            comment="#",
            header=None,
            names=["shortname", "name", "priority"],
        )

        attack_patterns = []
        for _, row in suricata_df.iterrows():
            attack_pattern_name = row["name"]
            attack_pattern = AICAAttackPattern(
                name=attack_pattern_name,
            )

            attack_patterns.append(attack_pattern)

        knowledge_to_neo(attack_patterns)
