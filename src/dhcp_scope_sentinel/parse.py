"""Bounded, fail-closed parser for untrusted JSON snapshots."""
from __future__ import annotations

import ipaddress
import json
import re
import os
import stat
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000
MAX_NODES = 35_000
MAX_DEPTH = 28
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


class InputError(ValueError):
    """Input cannot be interpreted safely. No partial report is produced."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in items:
        if key in obj:
            raise InputError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _bounded(node: Any) -> None:
    stack = [(node, 0)]
    nodes = 0
    while stack:
        cur, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InputError("JSON structure exceeds node or depth limit")
        if isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, depth + 1) for v in cur)


def load(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise InputError("input symlinks are not accepted")
    try:
        # O_NOFOLLOW closes the last-path-component symlink race on supported OSes;
        # nonblocking open avoids hanging on a path swapped for a FIFO.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise InputError(f"not a regular input file: {path}")
            if info.st_size > MAX_BYTES:
                raise InputError("input exceeds 2 MB")
            raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise InputError("input exceeds 2 MB")
        obj = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_pairs,
                         parse_constant=lambda x: (_ for _ in ()).throw(InputError(f"invalid JSON constant: {x}")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise InputError(f"could not read JSON: {exc}") from exc
    _bounded(obj)
    if not isinstance(obj, dict):
        raise InputError("snapshot root must be an object")
    return obj


def fields(obj: Any, allowed: set[str], required: set[str], ctx: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise InputError(f"{ctx}: expected object")
    missing, extra = required - obj.keys(), obj.keys() - allowed
    if missing or extra:
        raise InputError(f"{ctx}: missing={sorted(missing)} unknown={sorted(extra)}")
    return obj


def name(value: Any, ctx: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise InputError(f"{ctx}: expected identifier (letters, digits, ._:-; max 64)")
    return value


def ip(value: Any, ctx: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise InputError(f"{ctx}: expected IPv4 string")
    try:
        parsed = ipaddress.ip_address(value)
        if not isinstance(parsed, ipaddress.IPv4Address) or parsed.is_multicast or parsed.is_unspecified:
            raise ValueError("non-unicast IPv4")
        return parsed
    except ValueError as exc:
        raise InputError(f"{ctx}: invalid unicast IPv4: {value}") from exc


def net(value: Any, ctx: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise InputError(f"{ctx}: expected IPv4 CIDR")
    try:
        parsed = ipaddress.ip_network(value, strict=True)
        if not isinstance(parsed, ipaddress.IPv4Network) or parsed.prefixlen > 30:
            raise ValueError("unsupported IPv4 network (CIDR /31-/32)")
        if parsed.is_multicast or parsed.is_unspecified:
            raise ValueError("non-unicast network")
        return parsed
    except ValueError as exc:
        raise InputError(f"{ctx}: invalid IPv4 CIDR: {value}") from exc


def array(value: Any, ctx: str, limit: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > limit:
        raise InputError(f"{ctx}: expected array (maximum {limit})")
    return value


def flag(value: Any, ctx: str) -> bool:
    if type(value) is not bool:
        raise InputError(f"{ctx}: expected boolean")
    return value
