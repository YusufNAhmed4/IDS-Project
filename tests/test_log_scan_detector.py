"""
Tests port scan detector
"""

from detector import RepeatLogDetector

def make_tcp_event(
    timestamp: float,
    destination_port: int,
    source_ip: str = "10.0.0.5",
    destination_ip: str = "10.0.0.10",
    flags: str = "S",
) -> dict:
    """Build a minimal event for detector tests."""
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": destination_port,
        "tcp_flags": flags,
    }


def test_detects_port_scan() -> None:
    """Tests if detector can detect a RepeatLog."""
    detector = RepeatLogDetector(
        attempt_threshold=5,
        window_seconds=10.0,
    )

    alert = None

    for offset, port in enumerate([20, 21, 22, 23, 24]):
        alert = detector.process_event(
            make_tcp_event(
                timestamp=1000.0 + offset,
                destination_port=8000,
            )
        )

    assert alert is not None
    assert alert.source_ip == "10.0.0.5"
    assert alert.destination_ip == "10.0.0.10"
    assert alert.num_attempts == 5


def test_does_not_alert_below_threshold() -> None:
    """If there are too few logs, don't cause alert."""
    detector = RepeatLogDetector(
        attempt_threshold=5,
        window_seconds=10.0,
    )

    for offset, port in enumerate([20, 21, 22, 23]):
        alert = detector.process_event(
            make_tcp_event(
                timestamp=1000.0 + offset,
                destination_port=8000,
            )
        )

        assert alert is None


def test_repeated_port_counts_once() -> None:
    """Only count unique port accesses."""
    detector = RepeatLogDetector(
        attempt_threshold=3,
        window_seconds=10.0,
    )

    ports = [22, 23, 24, 80]

    alerts = [
        detector.process_event(
            make_tcp_event(
                timestamp=1000.0 + offset,
                destination_port=port,
            )
        )
        for offset, port in enumerate(ports)
    ]

    assert all(alert is None for alert in alerts)


def test_old_attempts_expire() -> None:
    """If an attempt is too old, remove it."""
    detector = RepeatLogDetector(
        attempt_threshold=3,
        window_seconds=5.0,
    )

    events = [
        make_tcp_event(1000.0, 20),
        make_tcp_event(1001.0, 20),
        make_tcp_event(1010.0, 20),
    ]

    alerts = [detector.process_event(event) for event in events]

    assert all(alert is None for alert in alerts)


def test_syn_ack_is_not_connection_attempt() -> None:
    """If TCP had an ACK, then don't count it."""
    detector = RepeatLogDetector(
        attempt_threshold=1,
        window_seconds=10.0,
    )

    alert = detector.process_event(
        make_tcp_event(
            timestamp=1000.0,
            destination_port=22,
            flags="SA",
        )
    )

    assert alert is None


def test_sources_are_tracked_separately() -> None:
    """If sources are different, don't consider a RepeatLog."""
    detector = RepeatLogDetector(
        attempt_threshold=3,
        window_seconds=10.0,
    )

    events = [
        make_tcp_event(1000.0, 20, source_ip="10.0.0.5"),
        make_tcp_event(1001.0, 21, source_ip="10.0.0.5"),
        make_tcp_event(1002.0, 22, source_ip="10.0.0.7"),
    ]

    alerts = [detector.process_event(event) for event in events]

    assert all(alert is None for alert in alerts)
