"""Probe plumbing: the decorator that ties a probe to its registry ID, and
the environment probes read the world through (swappable in tests)."""

import os
import platform
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import psycopg

from kit.model import Check, ProbeResult

Probe = Callable[[Check, "ProbeEnv"], ProbeResult]

PROBES: dict[str, Probe] = {}


def probe(check_id: str) -> Callable[[Probe], Probe]:
    def register(fn: Probe) -> Probe:
        if check_id in PROBES:
            raise ValueError(f"two probes registered for {check_id}")
        PROBES[check_id] = fn
        return fn

    return register


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text()
    except OSError:
        return None


@dataclass
class ProbeEnv:
    """Everything a probe touches outside its own arguments."""

    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    connect_db: Callable[..., psycopg.Connection] = psycopg.connect
    getaddrinfo: Callable[..., list] = socket.getaddrinfo
    create_connection: Callable[..., socket.socket] = socket.create_connection
    tls_context: Callable[[], ssl.SSLContext] = ssl.create_default_context
    machine: Callable[[], str] = platform.machine
    read_text: Callable[[str], str | None] = _read_text
