"""Explainable static checks; no network access, packet capture, or active probes."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Any

from .model import Interval, Scope, Segment, Snapshot
from .parse import InputError, array, fields, flag, ip, name, net

SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RULES: dict[str, tuple[str, str]] = {
    "DHCP001": ("high", "Overlapping dynamic allocation pools"),
    "DHCP002": ("high", "Failover peers have inconsistent scope definitions"),
    "DHCP003": ("high", "Scope server is not authorized for segment"),
    "DHCP004": ("high", "Dynamic pool includes protected infrastructure address"),
    "DHCP005": ("high", "Duplicate or conflicting DHCP reservation"),
    "DHCP006": ("medium", "Excluded range outside all dynamic pools"),
    "DHCP007": ("high", "Overlapping routed subnets in the same VRF"),
    "DHCP008": ("medium", "Reservation inside dynamic range without exclusion"),
    "DHCP009": ("high", "Overlapping intervals inside one scope"),
    "DHCP101": ("critical", "Observed unauthorized DHCP server identifier"),
    "DHCP102": ("critical", "Observed gateway option differs from approved gateway"),
    "DHCP103": ("high", "Observed offered address is outside approved allocations"),
    "DHCP104": ("high", "Observed offer uses protected static or gateway address"),
    "DHCP105": ("high", "Missing or untrusted relay identifier in observation"),
    "DHCP106": ("medium", "Multiple observed offers for the same address and different clients"),
    "DHCP107": ("high", "Observed DNS option diverges from authorized list"),
    "DHCP108": ("critical", "Observed offer assigns a reservation to a different client"),
    "DHCP201": ("high", "Contract requires trusted-relay enforcement"),
    "DHCP202": ("high", "Insufficient allocatable pool capacity"),
    "DHCP203": ("high", "Scope count exceeds approved change budget"),
    "DHCP204": ("high", "Contract DNS allowlist violation"),
    "DHCP205": ("high", "Contract requires an existing segment"),
    "DHCP206": ("critical", "Authorized server configuration drifts outside independent contract"),
    "DHCP207": ("critical", "Gateway or subnet diverges from independent contract"),
    "DHCP208": ("high", "Trusted relay configuration drifts outside independent contract"),
}


@dataclass(frozen=True)
class Finding:
    rule: str
    segment: str
    subject: str
    detail: str

    @property
    def severity(self) -> str:
        return RULES[self.rule][0]

    @property
    def fingerprint(self) -> str:
        canonical = "\x1f".join((self.rule, self.segment, self.subject, self.detail))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "title": RULES[self.rule][1], "severity": self.severity,
                "segment": self.segment, "subject": self.subject, "detail": self.detail,
                "fingerprint": self.fingerprint}


def _add(issues: dict[str, Finding], rule: str, seg: str, subj: str, detail: str) -> None:
    issue = Finding(rule, seg, subj, detail)
    issues[issue.fingerprint] = issue


def _same_group(a: Scope, b: Scope) -> bool:
    return a.failover is not None and a.failover == b.failover


def _intervals_identical(a: tuple[Interval, ...], b: tuple[Interval, ...]) -> bool:
    return set(a) == set(b)


def _in_intervals(ipaddr: IPv4Address, intervals: tuple[Interval, ...]) -> bool:
    return any(r.contains(ipaddr) for r in intervals)


def _allocatable(scope: Scope, address: IPv4Address) -> bool:
    return _in_intervals(address, scope.pools) and not _in_intervals(address, scope.exclusions)


def _capacity(segment: Segment) -> int:
    """Exact union of per-scope allocatable intervals, without expanding large CIDRs."""
    allocations: list[tuple[int, int]] = []
    for scope in segment.scopes:
        for pool in scope.pools:
            blocks = [(int(pool.start), int(pool.end))]
            for exclusion in scope.exclusions:
                lo, hi = int(exclusion.start), int(exclusion.end)
                remaining: list[tuple[int, int]] = []
                for start, end in blocks:
                    if hi < start or lo > end:
                        remaining.append((start, end))
                    else:
                        if start < lo:
                            remaining.append((start, lo - 1))
                        if hi < end:
                            remaining.append((hi + 1, end))
                blocks = remaining
            allocations.extend(blocks)
    if not allocations:
        return 0
    allocations.sort()
    merged: list[list[int]] = []
    for start, end in allocations:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    protected = {int(segment.gateway), *(int(h.address) for h in segment.static_hosts)}
    for scope in segment.scopes:
        protected.update(int(res.address) for res in scope.reservations)
    total = sum(end - start + 1 for start, end in merged)
    total -= sum(1 for address in protected if any(start <= address <= end for start, end in merged))
    return total


def audit(snapshot: Snapshot, contracts: tuple[dict[str, Any], ...] = ()) -> list[Finding]:
    issues: dict[str, Finding] = {}
    seg_by_id = {s.id: s for s in snapshot.segments}
    for segment in snapshot.segments:
        ident = segment.id
        all_scopes = segment.scopes
        approved = set(segment.authorized)
        protected = {segment.gateway: "gateway"}
        protected.update({host.address: "static host " + host.asset for host in segment.static_hosts})
        for s in all_scopes:
            if s.server not in approved:
                _add(issues, "DHCP003", ident, s.id, f"scope server {s.server} is not in authorized_servers")
            for idx, a in enumerate(s.pools):
                for b in s.pools[idx + 1:]:
                    if a.intersects(b):
                        _add(issues, "DHCP009", ident, s.id, f"self-overlap {a.start}-{a.end} with {b.start}-{b.end}")
                for address, label in protected.items():
                    if _allocatable(s, address):
                        _add(issues, "DHCP004", ident, f"{s.id}/{address}", f"dynamic allocation contains {label}")
            for exclusion in s.exclusions:
                if not any(exclusion.intersects(p) for p in s.pools):
                    _add(issues, "DHCP006", ident, f"{s.id}/{exclusion.start}-{exclusion.end}", "exclusion does not overlap any pool")
            for r in s.reservations:
                if _allocatable(s, r.address):
                    _add(issues, "DHCP008", ident, f"{s.id}/{r.address}", "reservation address is also dynamically allocatable")
        groups: dict[str, list[Scope]] = {}
        for peer in all_scopes:
            if peer.failover is not None:
                groups.setdefault(peer.failover, []).append(peer)
        for group, peers in groups.items():
            if len(peers) != 2:
                _add(issues, "DHCP002", ident, group, f"failover group must have exactly two peers; found {len(peers)}")
        # Cross-scope overlap is explicit failover only when configurations match.
        for i, scope in enumerate(all_scopes):
            for other in all_scopes[i + 1:]:
                pair = "/".join(sorted((scope.id, other.id)))
                overlaps = any(a.intersects(b) for a in scope.pools for b in other.pools)
                if _same_group(scope, other):
                    if not (_intervals_identical(scope.pools, other.pools) and
                            _intervals_identical(scope.exclusions, other.exclusions) and
                            set(scope.reservations) == set(other.reservations) and
                            scope.server != other.server):
                        _add(issues, "DHCP002", ident, pair, "failover peers must have identical pools, exclusions and reservations on distinct servers")
                elif overlaps:
                    _add(issues, "DHCP001", ident, pair, "non-failover dynamic pools overlap")
        addr_to_clients: dict[IPv4Address, set[str]] = {}
        client_to_addr: dict[str, set[IPv4Address]] = {}
        for scope in all_scopes:
            for r in scope.reservations:
                addr_to_clients.setdefault(r.address, set()).add(r.client)
                client_to_addr.setdefault(r.client, set()).add(r.address)
        for addr, clients in addr_to_clients.items():
            if len(clients) > 1:
                _add(issues, "DHCP005", ident, str(addr), "reservation IP belongs to multiple client identifiers")
        for client, addresses in client_to_addr.items():
            if len(addresses) > 1:
                _add(issues, "DHCP005", ident, client, "client identifier has conflicting reservation addresses")
    # VRF is a routing domain: overlapping subnets in different VRFs are intentional and permitted.
    for i, a in enumerate(snapshot.segments):
        for b in snapshot.segments[i + 1:]:
            if a.vrf == b.vrf and a.network.overlaps(b.network):
                _add(issues, "DHCP007", a.id, b.id, f"overlap in VRF {a.vrf}: {a.network} and {b.network}")

    offered_clients: dict[tuple[str, str], set[str]] = {}
    for offer in snapshot.offers:
        seg = seg_by_id[offer.segment]
        subj = f"{offer.server}/{offer.offered}/{offer.client}"
        if offer.server not in seg.authorized:
            _add(issues, "DHCP101", seg.id, str(offer.server), "observed server identifier is not authorized")
        if offer.router is not None and offer.router != seg.gateway:
            _add(issues, "DHCP102", seg.id, subj, f"router option {offer.router} differs from gateway {seg.gateway}")
        allowed_offer = any(_allocatable(s, offer.offered) or any(r.address == offer.offered for r in s.reservations)
                            for s in seg.scopes)
        other_clients = {r.client for scope in seg.scopes for r in scope.reservations
                         if r.address == offer.offered and r.client != offer.client}
        if other_clients and not any(r.address == offer.offered and r.client == offer.client
                                     for scope in seg.scopes for r in scope.reservations):
            _add(issues, "DHCP108", seg.id, subj, "observed offer targets an IP reserved for a different client")
        if not allowed_offer:
            _add(issues, "DHCP103", seg.id, subj, "offered IP not part of approved dynamic or reserved allocation")
        if offer.offered == seg.gateway or offer.offered in {h.address for h in seg.static_hosts}:
            _add(issues, "DHCP104", seg.id, subj, "offered IP is a protected gateway or static inventory address")
        if seg.require_relay and offer.relay not in seg.relays:
            _add(issues, "DHCP105", seg.id, subj, f"relay ID {offer.relay!r} is not in trusted_relays")
        if offer.dns and tuple(offer.dns) != seg.dns:
            _add(issues, "DHCP107", seg.id, subj, "observed DNS option differs from approved ordered DNS servers")
        offered_clients.setdefault((seg.id, str(offer.offered)), set()).add(offer.client)
    for (seg, addr), clients in offered_clients.items():
        if len(clients) > 1:
            _add(issues, "DHCP106", seg, addr, "same IP offered to multiple clients in supplied observations; OFFER is not an actual lease conflict")
    for contract in contracts:
        ident = contract["segment"]
        seg = seg_by_id.get(ident)
        if seg is None:
            _add(issues, "DHCP205", ident, ident, "required segment is absent from snapshot")
            continue
        if contract.get("must_require_relay", False) and not seg.require_relay:
            _add(issues, "DHCP201", ident, ident, "contract mandates require_relay=true")
        capacity = contract.get("min_usable_capacity")
        if capacity is not None and _capacity(seg) < capacity:
            _add(issues, "DHCP202", ident, ident, f"allocatable capacity {_capacity(seg)} is below minimum {capacity}")
        maximum = contract.get("max_scopes")
        if maximum is not None and len(seg.scopes) > maximum:
            _add(issues, "DHCP203", ident, ident, f"scope count {len(seg.scopes)} exceeds limit {maximum}")
        allowed_servers = contract.get("authorized_server_allowlist")
        if allowed_servers is not None and not set(seg.authorized).issubset(set(allowed_servers)):
            _add(issues, "DHCP206", ident, ident, "snapshot authorizes servers outside independent contract")
        gateway = contract.get("approved_gateway")
        network = contract.get("approved_network")
        if (gateway is not None and seg.gateway != gateway) or (network is not None and seg.network != network):
            _add(issues, "DHCP207", ident, ident, "gateway or subnet diverges from independent contract")
        relays = contract.get("trusted_relay_allowlist")
        if relays is not None and not set(seg.relays).issubset(set(relays)):
            _add(issues, "DHCP208", ident, ident, "snapshot trusts relays outside independent contract")
        dns = contract.get("dns_allowlist")
        if dns is not None and not set(seg.dns).issubset(set(dns)):
            _add(issues, "DHCP204", ident, ident, "segment DNS configuration contains addresses outside the contract allowlist")
    return sorted(issues.values(), key=lambda x: (x.segment, x.rule, x.subject, x.detail))


def parse_contracts(raw: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    root = fields(raw, {"schema_version", "contracts"}, {"schema_version", "contracts"}, "policy")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise InputError("policy: expected schema_version integer 1")
    parsed: list[dict[str, Any]] = []
    for item in array(root["contracts"], "contracts", 200):
        ctx = "contract"
        allowed = {"segment", "min_usable_capacity", "max_scopes", "must_require_relay", "dns_allowlist", "authorized_server_allowlist", "approved_gateway", "approved_network", "trusted_relay_allowlist"}
        item = fields(item, allowed, {"segment"}, ctx)
        contract: dict[str, Any] = {"segment": name(item["segment"], ctx + ".segment")}
        for key in ("min_usable_capacity", "max_scopes"):
            if key in item:
                value = item[key]
                if type(value) is not int or not 0 <= value <= 2**32:
                    raise InputError(f"{ctx}.{key}: expected bounded nonnegative integer")
                contract[key] = value
        if "must_require_relay" in item:
            contract["must_require_relay"] = flag(item["must_require_relay"], ctx + ".must_require_relay")
        if "authorized_server_allowlist" in item:
            contract["authorized_server_allowlist"] = tuple(ip(v, ctx + ".authorized_server_allowlist") for v in array(item["authorized_server_allowlist"], ctx + ".authorized_server_allowlist", 16))
        if "approved_gateway" in item:
            contract["approved_gateway"] = ip(item["approved_gateway"], ctx + ".approved_gateway")
        if "approved_network" in item:
            contract["approved_network"] = net(item["approved_network"], ctx + ".approved_network")
        if "trusted_relay_allowlist" in item:
            contract["trusted_relay_allowlist"] = tuple(name(v, ctx + ".trusted_relay_allowlist") for v in array(item["trusted_relay_allowlist"], ctx + ".trusted_relay_allowlist", 64))
        if "dns_allowlist" in item:
            contract["dns_allowlist"] = tuple(ip(v, ctx + ".dns_allowlist") for v in array(item["dns_allowlist"], ctx + ".dns_allowlist", 16))
        parsed.append(contract)
    ids = [x["segment"] for x in parsed]
    if len(ids) != len(set(ids)):
        raise InputError("policy: duplicate segment contracts")
    return tuple(parsed)
