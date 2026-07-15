"""
The actual detector. Uses a deque to check if a src IP 
has sent too many unacknowledged packets to various ports.
"""

# pylint: disable=invalid-name

from __future__ import annotations

from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class PortAlert :
    """Info describing a possible port scan issue."""

    source_ip: str
    destination_ip: str
    first_seen_time: float
    last_seen_time: float
    unique_ports: tuple[int, ...]


class PortScanDetector :
    """
    Detect one source trying to access too many dest ports.
    Only TCP packets which haven't been ACKed are considered.
    """

    def __init__ (
            self,
            port_threshold: 10,
            window_seconds: 10.0
    ) -> None :
        if port_threshold <= 0 :
            raise ValueError("port_threshold must be > 0")
        if window_seconds <= 0.0 :
            raise ValueError("window_seconds must be > 0.0")

        self.port_threshold = port_threshold
        self.window_seconds = window_seconds


        # key: (source IP, dest IP)
        # value: deque((timestamp, dest port))
        self._attempts: dict[
            tuple[str, str],
            deque[tuple[float, int]],
        ] = defaultdict(deque)

        self._alerted_keys: set[tuple[str, str]] = set()

    def process_event(self, event: dict[str, Any]) -> PortAlert | None :
        """Processes one event and possibly returns an alert."""
        if not self.is_tcp_connection_attempt(event) :
            return None

        timestamp = float(event.get("timestamp"))
        source_IP = str(event.get("source_ip"))
        dest_IP = str(event.get("destination_ip"))
        dest_port = int(event.get("destination_port"))

        key = (source_IP, dest_IP)
        attempts = self._attempts[key]

        attempts.append((timestamp, dest_port))
        self._remove_expired_attempts(attempts, timestamp)

        distinct_ports = sorted({port for _, port in attempts})

        if len(distinct_ports) < self.port_threshold :
            #If below threshold, throw out alert
            self._alerted_keys.discard(key)
            return None

        if key in self._alerted_keys :
            return None

        self._alerted_keys.add(key)

        return PortAlert(
            source_ip=source_IP,
            destination_ip=dest_IP,
            first_seen_time=attempts[0][0],
            last_seen_time=attempts[-1][0],
            unique_ports=tuple(distinct_ports)
        )

    def _remove_expired_attempts(
            self,
            attempts: deque[tuple[float, int]],
            current_time: float
        ) -> None :
        """Removes old attempts from attempt deque."""
        cutoff = current_time - self.window_seconds
        while attempts and attempts[0][0] < cutoff :
            attempts.popleft()


    @staticmethod
    def is_tcp_connection_attempt(event: dict[str, Any]) -> bool :
        """Checks whether an event is a TCP connection without an ACK"""
        if event.get("protocol") != "TCP" :
            return False
        if event.get("destination_port") is None :
            return False

        flags = str(event.get("tcp_flags") or "")
        return "S" in flags and "A" not in flags
