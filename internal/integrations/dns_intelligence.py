"""DNS intelligence module for reconnaissance."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

import httpx

from internal.utils.logging import get_logger
from internal.utils.security import validate_domain

logger = get_logger(module="dns_intelligence")

# Common DNS record types
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV"]

# Public DNS APIs for resolution
DNS_OVER_HTTPS_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# ASN lookup API
ASN_API_URL = "https://api.hackertarget.com/aslookup/?q={ip}"

# Zone transfer common nameservers
ZONE_TRANSFER_PORTS = [53]


@dataclass
class DNSRecord:
    """DNS record entry."""

    name: str
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class ZoneTransferResult:
    """DNS zone transfer attempt result."""

    domain: str
    nameserver: str
    success: bool
    records: list[DNSRecord] = field(default_factory=list)
    error: str = ""


@dataclass
class ASNInfo:
    """Autonomous System Number information."""

    ip: str
    asn: str = ""
    asn_name: str = ""
    country: str = ""
    registry: str = ""
    cidr: str = ""


@dataclass
class DNSIntelligenceResult:
    """Complete DNS intelligence for a domain."""

    domain: str
    records: dict[str, list[DNSRecord]] = field(default_factory=dict)
    zone_transfers: list[ZoneTransferResult] = field(default_factory=list)
    asn_info: ASNInfo | None = None
    subdomains: list[str] = field(default_factory=list)
    reverse_dns: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class DNSIntelligence:
    """Gathers DNS intelligence for reconnaissance targets.

    Capabilities:
    - DNS record enumeration via DoH
    - Zone transfer attempt (AXFR)
    - ASN/country lookup
    - Reverse DNS resolution
    - Subdomain brute-force (optional)
    """

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    async def gather(self, domain: str) -> DNSIntelligenceResult:
        """Gather all DNS intelligence for a domain."""
        domain = validate_domain(domain)
        result = DNSIntelligenceResult(domain=domain)

        # Parallel DNS resolution
        await self._resolve_records(domain, result)

        # ASN lookup
        await self._lookup_asn(domain, result)

        # Zone transfer check
        await self._check_zone_transfer(domain, result)

        # Reverse DNS
        await self._reverse_dns(domain, result)

        return result

    async def _resolve_records(self, domain: str, result: DNSIntelligenceResult) -> None:
        """Resolve all common DNS record types."""
        for record_type in DNS_RECORD_TYPES:
            try:
                records = await self._resolve_dns(domain, record_type)
                if records:
                    result.records[record_type] = records
            except Exception as e:
                result.errors.append(f"{record_type} resolution failed: {e}")

    async def _resolve_dns(self, domain: str, record_type: str) -> list[DNSRecord]:
        """Resolve DNS records using DNS-over-HTTPS."""
        records: list[DNSRecord] = []

        for doh_url in DNS_OVER_HTTPS_URLS:
            try:
                params = {"name": domain, "type": record_type}
                headers = {"Accept": "application/dns-json"}

                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(doh_url, params=params, headers=headers)

                    if response.status_code == 200:
                        data = response.json()
                        for answer in data.get("Answer", []):
                            records.append(DNSRecord(
                                name=answer.get("name", domain),
                                record_type=record_type,
                                value=answer.get("data", ""),
                                ttl=answer.get("TTL", 0),
                            ))

                        if records:
                            break  # Success with this resolver

            except Exception as e:
                logger.debug("doh_resolution_failed", url=doh_url, error=str(e))
                continue

        # Fallback: use socket for A records
        if not records and record_type == "A":
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                seen = set()
                for family, _, _, _, sockaddr in ips:
                    ip = sockaddr[0]
                    if ip not in seen:
                        seen.add(ip)
                        records.append(DNSRecord(
                            name=domain,
                            record_type="A",
                            value=ip,
                        ))
            except socket.gaierror:
                pass

        return records

    async def _lookup_asn(self, domain: str, result: DNSIntelligenceResult) -> None:
        """Look up ASN information for domain IPs."""
        # First resolve A records
        a_records = result.records.get("A", [])
        if not a_records:
            a_records = await self._resolve_dns(domain, "A")

        if a_records:
            ip = a_records[0].value
            try:
                asn_info = await self._lookup_asn_ip(ip)
                if asn_info:
                    result.asn_info = asn_info
            except Exception as e:
                result.errors.append(f"ASN lookup failed: {e}")

    async def _lookup_asn_ip(self, ip: str) -> ASNInfo | None:
        """Look up ASN information for an IP address."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    ASN_API_URL.format(ip=ip),
                    follow_redirects=True,
                )
                if response.status_code == 200:
                    text = response.text.strip()
                    parts = text.split("|")
                    if len(parts) >= 3:
                        return ASNInfo(
                            ip=ip,
                            asn=parts[0].strip(),
                            asn_name=parts[1].strip(),
                            country=parts[2].strip(),
                        )
        except Exception as e:
            logger.debug("asn_lookup_failed", ip=ip, error=str(e))

        return None

    async def _check_zone_transfer(self, domain: str, result: DNSIntelligenceResult) -> None:
        """Attempt DNS zone transfer on nameservers."""
        ns_records = result.records.get("NS", [])
        if not ns_records:
            return

        for ns_record in ns_records:
            ns = ns_record.value.rstrip(".")
            try:
                zr = await self._attempt_zone_transfer(domain, ns)
                result.zone_transfers.append(zr)
            except Exception as e:
                result.zone_transfers.append(ZoneTransferResult(
                    domain=domain,
                    nameserver=ns,
                    success=False,
                    error=str(e),
                ))

    async def _attempt_zone_transfer(self, domain: str, nameserver: str) -> ZoneTransferResult:
        """Attempt an AXFR zone transfer."""
        # This is a simplified check - full implementation would use dnspython
        result = ZoneTransferResult(
            domain=domain,
            nameserver=nameserver,
            success=False,
            error="Zone transfer not supported in basic mode (requires dnspython)",
        )

        # Check if port 53 is open on nameserver
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            ns_ip = socket.gethostbyname(nameserver)
            sock.connect((ns_ip, 53))
            sock.close()
            result.error = "Port 53 open - zone transfer possible with dnspython"
        except (socket.timeout, socket.error, OSError):
            result.error = "Nameserver unreachable"

        return result

    async def _reverse_dns(self, domain: str, result: DNSIntelligenceResult) -> None:
        """Perform reverse DNS on resolved IPs."""
        a_records = result.records.get("A", [])
        for record in a_records:
            try:
                hostname = socket.gethostbyaddr(record.value)[0]
                result.reverse_dns[record.value] = hostname
            except socket.herror:
                result.reverse_dns[record.value] = "no reverse"
            except Exception:
                pass
