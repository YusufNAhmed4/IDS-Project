"""
basic tests for packet_sniffer
"""

# pylint: disable=no-name-in-module

from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Raw

from packet_sniffer import parse_packet

def test_tcp_syn_packet() -> None:
    """A TCP SYN packet should expose addresses, ports, and flags."""
    packet = (
        IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=50000, dport=22, flags="S")
    )

    event = parse_packet(packet)

    assert event is not None
    assert event["ip_version"] == "IPv4"
    assert event["source_ip"] == "10.0.0.5"
    assert event["destination_ip"] == "10.0.0.10"
    assert event["protocol"] == "TCP"
    assert event["source_port"] == 50000
    assert event["destination_port"] == 22
    assert event["tcp_flags"] == "S"


def test_tcp_syn_ack_packet() -> None:
    """A SYN-ACK response should preserve both TCP flags."""
    packet = (
        IP(src="10.0.0.10", dst="10.0.0.5")
        / TCP(sport=22, dport=50000, flags="SA")
    )

    event = parse_packet(packet)

    assert event is not None
    assert event["protocol"] == "TCP"
    assert event["source_port"] == 22
    assert event["destination_port"] == 50000
    assert event["tcp_flags"] == "SA"


def test_udp_dns_packet() -> None:
    """A UDP DNS-like packet should expose port 53."""
    packet = (
        IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
    )

    event = parse_packet(packet)

    assert event is not None
    assert event["protocol"] == "UDP"
    assert event["source_ip"] == "10.0.0.5"
    assert event["destination_ip"] == "8.8.8.8"
    assert event["source_port"] == 53000
    assert event["destination_port"] == 53
    assert event["tcp_flags"] is None


def test_icmp_echo_request() -> None:
    """An ICMP echo request should have type 8 and code 0."""
    packet = (
        IP(src="10.0.0.5", dst="10.0.0.10")
        / ICMP(type=8, code=0)
    )

    event = parse_packet(packet)

    assert event is not None
    assert event["protocol"] == "ICMP"
    assert event["icmp_type"] == 8
    assert event["icmp_code"] == 0
    assert event["source_port"] is None
    assert event["destination_port"] is None


def test_ipv6_tcp_packet() -> None:
    """The parser should also understand IPv6 TCP packets."""
    packet = (
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=42000, dport=443, flags="S")
    )

    event = parse_packet(packet)

    assert event is not None
    assert event["ip_version"] == "IPv6"
    assert event["source_ip"] == "2001:db8::1"
    assert event["destination_ip"] == "2001:db8::2"
    assert event["protocol"] == "TCP"
    assert event["destination_port"] == 443


def test_packet_with_payload() -> None:
    """Adding application data should not break metadata parsing."""
    packet = (
        IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=51000, dport=8000, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    )

    event = parse_packet(packet)

    assert event is not None
    assert event["protocol"] == "TCP"
    assert event["destination_port"] == 8000
    assert event["tcp_flags"] == "PA"
    assert event["packet_length"] > 0


def test_non_ip_packet_is_ignored() -> None:
    """ARP is not IPv4 or IPv6, so the parser should ignore it."""
    packet = ARP(
        psrc="10.0.0.5",
        pdst="10.0.0.10",
    )

    event = parse_packet(packet)

    assert event is None
