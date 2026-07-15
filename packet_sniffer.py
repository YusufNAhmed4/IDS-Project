"""
A packer sniffer which checks packets for malicious intent,
e.g. port scanning, brute-forcing logins.
"""

# pylint: disable=invalid-name
# pylint: disable=no-name-in-module

from __future__ import annotations

from typing import Any
from scapy.all import ICMP, IP, IPv6, TCP, UDP, Packet
from detector import PortScanDetector

port_scan_detector = PortScanDetector(
    port_threshold=10,
    window_seconds=10.0,
)

def parse_packet(packet: Packet) -> dict[str, Any] | None :
    """
    Takes a packet and turns it into a JSON-style dict.

    Returns None for anything that isn't IPv4 or IPv6.
    """
    if IP in packet :
        source_IP = packet[IP].src
        dest_IP = packet[IP].dst
        ip_vers = "IPv4"
    elif IPv6 in packet :
        source_IP = packet[IPv6].src
        dest_IP = packet[IPv6].dst
        ip_vers = "IPv6"
    else :
        # Neither IPv4 or IPv6 = return None
        return None

    event: dict[str, Any] = {
        "timestamp": float(packet.time),
        "source_ip": source_IP,
        "destination_ip": dest_IP,
        "ip_version": ip_vers,
        "protocol": "OTHER", 
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "packet_length": len(packet)
    }
    if TCP in packet :
        event["protocol"] = "TCP"
        event["source_port"] = int(packet[TCP].sport)
        event["destination_port"] = int(packet[TCP].dport)
        event["tcp_flags"] = str(packet[TCP].flags)
    elif UDP in packet :
        event["protocol"] = "UDP"
        event["source_port"] = int(packet[UDP].sport)
        event["destination_port"] = int(packet[UDP].dport)
    if ICMP in packet :
        event["protocol"] = "ICMP"
        event["icmp_type"] = int(packet[ICMP].type)
        event["icmp_code"] = int(packet[ICMP].code)

    return event


def process_packet(packet: Packet) -> None :
    """
    Parses and prints one packet.
    """
    event = parse_packet(packet)
    if event is None:
        return

    source = event["source_ip"]
    dest = event["destination_ip"]

    if event["source_port"] is not None :
        source = f"{source}:{event['source_port']}"
    if event["destination_port"] is not None :
        dest = f"{dest}:{event['destination_port']}"

    output =  (
        f"{event['ip_version']} | "
        f"{event['protocol']} | "
        f"{source} -> {dest} | "
        f"length={event['packet_length']}"
    )

    if event["tcp_flags"] is not None :
        output += f" | flags={event['tcp_flags']}"
    if event["type"] == "ICMP":
        output += (
            f" | type={event['icmp_type']}"
            f" | code={event['icmp_code']}"
        )

    print(output)

    alert = port_scan_detector.process_event(event)
    if alert is not None :
        print(
            "[ALERT] Possible port scan: "
            f"{alert.source_ip} contacted "
            f"{len(alert.unique_ports)} ports on "
            f"{alert.destination_ip}. "
            f"Ports: {alert.unique_ports}"
        )
