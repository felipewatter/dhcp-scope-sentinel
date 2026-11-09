"""Typed immutable DHCP scope and normalized observation model."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from .parse import InputError, array, fields, flag, ip, name, net


def _host(address: IPv4Address, network: IPv4Network, ctx: str) -> None:
    if address not in network or address in (network.network_address, network.broadcast_address):
        raise InputError(f"{ctx}: address {address} is not a usable host in {network}")


@dataclass(frozen=True)
class Interval:
    start: IPv4Address
    end: IPv4Address

    def contains(self, addr: IPv4Address) -> bool:
        return self.start <= addr <= self.end

    def intersects(self, other: "Interval") -> bool:
        return self.start <= other.end and other.start <= self.end

    @property
    def size(self) -> int:
        return int(self.end) - int(self.start) + 1


def _interval(value: Any, network: IPv4Network, ctx: str) -> Interval:
    entry = array(value, ctx, 2)
    if len(entry) != 2:
        raise InputError(f"{ctx}: interval must have exactly two addresses")
    start, end = ip(entry[0], ctx + " start"), ip(entry[1], ctx + " end")
    _host(start, network, ctx)
    _host(end, network, ctx)
    if start > end:
        raise InputError(f"{ctx}: interval start follows end")
    return Interval(start, end)


@dataclass(frozen=True)
class Reservation:
    address: IPv4Address
    client: str


@dataclass(frozen=True)
class Scope:
    id: str
    server: IPv4Address
    pools: tuple[Interval, ...]
    exclusions: tuple[Interval, ...]
    reservations: tuple[Reservation, ...]
    failover: str | None


@dataclass(frozen=True)
class Offer:
    segment: str
    server: IPv4Address
    offered: IPv4Address
    client: str
    router: IPv4Address | None
    relay: str | None
    dns: tuple[IPv4Address, ...]


@dataclass(frozen=True)
class StaticHost:
    address: IPv4Address
    asset: str


@dataclass(frozen=True)
class Segment:
    id: str
    vrf: str
    vlan: int
    network: IPv4Network
    gateway: IPv4Address
    dns: tuple[IPv4Address, ...]
    authorized: tuple[IPv4Address, ...]
    relays: tuple[str, ...]
    require_relay: bool
    scopes: tuple[Scope, ...]
    static_hosts: tuple[StaticHost, ...]


@dataclass(frozen=True)
class Snapshot:
    segments: tuple[Segment, ...]
    offers: tuple[Offer, ...]


def _unique(items: list[Any] | tuple[Any, ...], ctx: str) -> None:
    if len(items) != len(set(items)):
        raise InputError(f"{ctx}: duplicate entries")


def _parse_scope(raw: Any, network: IPv4Network, ctx: str) -> Scope:
    obj = fields(raw, {"id", "server", "pools", "exclusions", "reservations", "failover_group"},
                 {"id", "server", "pools", "exclusions", "reservations"}, ctx)
    ident = name(obj["id"], ctx + ".id")
    ranges = tuple(_interval(x, network, ctx + ".pools") for x in array(obj["pools"], ctx + ".pools", 300))
    exclusions = tuple(_interval(x, network, ctx + ".exclusions") for x in array(obj["exclusions"], ctx + ".exclusions", 300))
    reservations: list[Reservation] = []
    for item in array(obj["reservations"], ctx + ".reservations", 1000):
        item = fields(item, {"ip", "client_id"}, {"ip", "client_id"}, ctx + ".reservation")
        addr = ip(item["ip"], ctx + ".reservation.ip")
        _host(addr, network, ctx + ".reservation.ip")
        reservations.append(Reservation(addr, name(item["client_id"], ctx + ".reservation.client_id")))
    if not ranges and not reservations:
        raise InputError(f"{ctx}: scope requires at least one pool or reservation")
    failover = obj.get("failover_group")
    if failover is not None:
        failover = name(failover, ctx + ".failover_group")
    return Scope(ident, ip(obj["server"], ctx + ".server"), ranges, exclusions, tuple(reservations), failover)


def _parse_segment(raw: Any, ctx: str) -> Segment:
    allowed = {"id", "vrf", "vlan", "network", "gateway", "dns_servers", "authorized_servers",
               "trusted_relays", "require_relay", "scopes", "static_hosts"}
    required = allowed - {"static_hosts", "trusted_relays", "require_relay"}
    obj = fields(raw, allowed, required, ctx)
    network = net(obj["network"], ctx + ".network")
    gateway = ip(obj["gateway"], ctx + ".gateway")
    _host(gateway, network, ctx + ".gateway")
    vlan = obj["vlan"]
    if type(vlan) is not int or not 1 <= vlan <= 4094:
        raise InputError(f"{ctx}.vlan: expected 1..4094")
    dns = tuple(ip(x, ctx + ".dns_servers") for x in array(obj["dns_servers"], ctx + ".dns_servers", 16))
    authorized = tuple(ip(x, ctx + ".authorized_servers") for x in array(obj["authorized_servers"], ctx + ".authorized_servers", 16))
    if not authorized:
        raise InputError(f"{ctx}.authorized_servers: at least one required")
    relays = tuple(name(x, ctx + ".trusted_relays") for x in array(obj.get("trusted_relays", []), ctx + ".trusted_relays", 64))
    _unique(authorized, ctx + ".authorized_servers")
    _unique(relays, ctx + ".trusted_relays")
    scopes = tuple(_parse_scope(x, network, ctx + ".scope") for x in array(obj["scopes"], ctx + ".scopes", 200))
    if not scopes:
        raise InputError(f"{ctx}.scopes: at least one scope required")
    _unique([s.id for s in scopes], ctx + ".scopes.id")
    hosts = []
    for entry in array(obj.get("static_hosts", []), ctx + ".static_hosts", 2000):
        entry = fields(entry, {"ip", "asset"}, {"ip", "asset"}, ctx + ".static_host")
        address = ip(entry["ip"], ctx + ".static_host.ip")
        _host(address, network, ctx + ".static_host.ip")
        hosts.append(StaticHost(address, name(entry["asset"], ctx + ".static_host.asset")))
    _unique([h.address for h in hosts], ctx + ".static_hosts.ip")
    required_relay = flag(obj.get("require_relay", False), ctx + ".require_relay")
    if required_relay and not relays:
        raise InputError(f"{ctx}: require_relay needs trusted_relays")
    return Segment(name(obj["id"], ctx + ".id"), name(obj["vrf"], ctx + ".vrf"), vlan,
                   network, gateway, dns, authorized, relays, required_relay, scopes, tuple(hosts))


def parse(raw: dict[str, Any]) -> Snapshot:
    root = fields(raw, {"schema_version", "segments", "observations"},
                  {"schema_version", "segments"}, "snapshot")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise InputError("unsupported schema_version (expected integer 1)")
    segments = tuple(_parse_segment(item, "segment") for item in array(root["segments"], "segments", 200))
    if not segments:
        raise InputError("segments: at least one required")
    _unique([s.id for s in segments], "segments.id")
    seen_segment = {s.id: s for s in segments}
    offers: list[Offer] = []
    for i, entry in enumerate(array(root.get("observations", []), "observations", 5000)):
        ctx = f"observations[{i}]"
        entry = fields(entry, {"segment", "server_ip", "offered_ip", "client_id", "router", "relay_id", "dns_servers"},
                       {"segment", "server_ip", "offered_ip", "client_id"}, ctx)
        segment = name(entry["segment"], ctx + ".segment")
        if segment not in seen_segment:
            raise InputError(f"{ctx}: unknown segment '{segment}'")
        router = ip(entry["router"], ctx + ".router") if "router" in entry else None
        relay = name(entry["relay_id"], ctx + ".relay_id") if "relay_id" in entry else None
        dns = tuple(ip(x, ctx + ".dns_servers") for x in array(entry.get("dns_servers", []), ctx + ".dns_servers", 16))
        offers.append(Offer(segment, ip(entry["server_ip"], ctx + ".server_ip"),
                            ip(entry["offered_ip"], ctx + ".offered_ip"),
                            name(entry["client_id"], ctx + ".client_id"), router, relay, dns))
    return Snapshot(segments, tuple(offers))
