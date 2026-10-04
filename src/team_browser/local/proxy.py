"""Fail-closed validation of trusted, browser-context proxy probe evidence.

This module deliberately does not implement a proxy or claim to enforce network
isolation. A future probe must observe the exact browser/profile/runtime context,
including DNS, IPv4/IPv6, WebRTC/UDP, and a failed-proxy/direct-fallback test.
An HTTP IP-echo test alone is insufficient. Missing evidence always blocks.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

from .secrets import SecretRef
from .storage import validate_identifier


@dataclass(frozen=True)
class ProxyConfiguration:
    proxy_id: str
    scheme: Literal["http", "https", "socks5"]
    host: str
    port: int
    credentials: SecretRef | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_identifier(self.proxy_id)
        if self.scheme not in ("http", "https", "socks5"):
            raise ValueError("Unsupported proxy scheme")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("Proxy port must be an integer between 1 and 65535")
        if not isinstance(self.host, str) or not self.host or len(self.host) > 253:
            raise ValueError("A bounded proxy hostname or IP address is required")
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            if not all(
                re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in self.host.split(".")
            ):
                raise ValueError(
                    "Proxy host must not contain a URL, credentials, or path"
                ) from None
        if "%" in self.host:
            raise ValueError("Scoped proxy IP addresses are not supported")

    @property
    def endpoint(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def fingerprint(self) -> str:
        # Bind to a secret reference, never the secret's value. Rotating credentials
        # should also replace the reference or invalidate existing evidence.
        data = [
            self.proxy_id,
            self.scheme,
            self.host.lower(),
            self.port,
            self.credentials.account_id if self.credentials else None,
        ]
        return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class ProxyExpectations:
    profile_id: str
    runtime_sha256: str
    expected_exit_networks: tuple[str, ...]
    direct_exit_ips: tuple[str, ...]
    max_evidence_age: timedelta = timedelta(seconds=60)

    def __post_init__(self) -> None:
        validate_identifier(self.profile_id)
        if not re.fullmatch(r"[0-9a-f]{64}", self.runtime_sha256):
            raise ValueError("The runtime SHA-256 must be pinned for the probe")
        if not self.expected_exit_networks or not self.direct_exit_ips:
            raise ValueError("Expected proxy networks and direct-route baseline IPs are required")
        for network in self.expected_exit_networks:
            parsed = ipaddress.ip_network(network, strict=True)
            if parsed.prefixlen == 0:
                raise ValueError("Catch-all exit networks cannot establish the intended route")
        for address in self.direct_exit_ips:
            ipaddress.ip_address(address)
        if not timedelta(0) < self.max_evidence_age <= timedelta(minutes=5):
            raise ValueError("Proxy evidence lifetime must be between zero and five minutes")


@dataclass(frozen=True)
class ProxyProbeEvidence:
    """Produced by a trusted probe implementation, not accepted from the cloud API."""

    profile_id: str
    runtime_sha256: str
    proxy_fingerprint: str
    observed_at: datetime
    observed_exit_ips: tuple[str, ...]
    probe_scope: str = "browser-context"
    route_verified: bool = False
    dns_via_proxy: bool = False
    webrtc_udp_blocked: bool = False
    ipv6_routed_or_blocked: bool = False
    direct_fallback_blocked: bool = False
    tls_verified: bool = False


class ProxyProbe(Protocol):
    def collect(
        self,
        configuration: ProxyConfiguration,
        expectations: ProxyExpectations,
    ) -> ProxyProbeEvidence: ...


@dataclass(frozen=True)
class PreflightResult:
    passed: bool
    blockers: tuple[str, ...]
    proxy_fingerprint: str
    profile_id: str
    runtime_sha256: str
    checked_at: datetime
    valid_until: datetime | None


def validate_proxy_preflight(
    configuration: ProxyConfiguration,
    expectations: ProxyExpectations,
    evidence: ProxyProbeEvidence | None,
    *,
    now: datetime | None = None,
) -> PreflightResult:
    """Validate bounded, current evidence. No network traffic is generated."""
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("An aware timestamp is required")
    blockers: list[str] = []
    valid_until = None
    if evidence is None:
        blockers.append("No browser-context proxy probe evidence is available")
    else:
        if evidence.profile_id != expectations.profile_id:
            blockers.append("Probe profile does not match")
        if evidence.runtime_sha256 != expectations.runtime_sha256:
            blockers.append("Probe runtime does not match")
        if evidence.proxy_fingerprint != configuration.fingerprint:
            blockers.append("Probe proxy configuration does not match")
        if evidence.probe_scope != "browser-context":
            blockers.append("Probe did not run in the browser context")
        if evidence.observed_at.utcoffset() is None:
            blockers.append("Probe timestamp has no timezone")
        else:
            age = now - evidence.observed_at
            if age < timedelta(0) or age > expectations.max_evidence_age:
                blockers.append("Probe evidence is stale or future-dated")
            valid_until = evidence.observed_at + expectations.max_evidence_age
        checks = (
            (evidence.route_verified, "Proxy route was not verified"),
            (evidence.dns_via_proxy, "DNS proxy routing was not verified"),
            (evidence.webrtc_udp_blocked, "WebRTC/UDP leak prevention was not verified"),
            (evidence.ipv6_routed_or_blocked, "IPv6 routing or blocking was not verified"),
            (evidence.direct_fallback_blocked, "Failed-proxy direct fallback was not blocked"),
            (evidence.tls_verified, "Probe HTTPS peer verification was not established"),
        )
        blockers.extend(reason for passed, reason in checks if passed is not True)
        expected_networks = tuple(
            ipaddress.ip_network(n) for n in expectations.expected_exit_networks
        )
        direct_ips = {ipaddress.ip_address(ip) for ip in expectations.direct_exit_ips}
        # An IPv4-mapped IPv6 form cannot conceal the same direct-route address.
        direct_ips.update(
            ip.ipv4_mapped
            for ip in tuple(direct_ips)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
        )
        if not evidence.observed_exit_ips:
            blockers.append("The probe did not observe an exit IP")
        for raw_ip in evidence.observed_exit_ips:
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                blockers.append("Probe reported an invalid exit IP")
                continue
            mapped_ip = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
            if ip in direct_ips or (mapped_ip is not None and mapped_ip in direct_ips):
                blockers.append("Probe observed the direct-route baseline IP")
            if not any(ip.version == net.version and ip in net for net in expected_networks):
                blockers.append("Probe exit IP is outside the expected proxy networks")
    return PreflightResult(
        not blockers,
        tuple(dict.fromkeys(blockers)),
        configuration.fingerprint,
        expectations.profile_id,
        expectations.runtime_sha256,
        now,
        valid_until if not blockers else None,
    )
