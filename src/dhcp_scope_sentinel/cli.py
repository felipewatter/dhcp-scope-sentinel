"""Command-line auditor with fail-closed exits and safe atomic output files."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .engine import SEVERITIES, audit, parse_contracts
from .model import parse
from .parse import InputError, load
from .report import audit_report, diff_report, sarif


def _emit(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _write(path: Path, body: str, protected: list[Path]) -> None:
    """Refuse input/output aliasing, links and pre-existing files; atomically create new output."""
    try:
        dest = path.resolve(strict=False)
        if any(dest == candidate.resolve(strict=False) for candidate in protected):
            raise InputError("output path would overwrite an input file")
        if path.is_symlink() or path.exists():
            raise InputError(f"output already exists; refusing overwrite: {path}")
        parent = path.parent
        if not parent.is_dir() or parent.is_symlink():
            raise InputError(f"output parent is not a regular directory: {parent}")
        if not path.name or path.name in (".", ".."):
            raise InputError("invalid output name")
        fd, temp = tempfile.mkstemp(prefix=".dhcp-scope-sentinel-", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                file.write(body)
                file.flush()
                os.fsync(file.fileno())
            # Link()/unlink() does not replace an existing destination even under races.
            os.link(temp, path)
        finally:
            os.unlink(temp)
    except FileExistsError as exc:
        raise InputError(f"output appeared concurrently, refusing overwrite: {path}") from exc
    except OSError as exc:
        raise InputError(f"could not write output safely: {exc}") from exc


def _fail(items: list[Any], threshold: str) -> bool:
    return threshold != "none" and any(SEVERITIES[x.severity] >= SEVERITIES[threshold] for x in items)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dhcp-scope-sentinel", description="Offline DHCPv4 configuration and offer audit")
    parser.add_argument("--version", action="version", version=f"dhcp-scope-sentinel {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("audit", "diff"):
        action = commands.add_parser(command, help="audit a snapshot" if command == "audit" else "compare two snapshots")
        if command == "audit":
            action.add_argument("snapshot", type=Path)
        else:
            action.add_argument("baseline", type=Path)
            action.add_argument("candidate", type=Path)
            action.add_argument("--all-findings", action="store_true", help="gate on persistent findings too")
        action.add_argument("--policy", type=Path, help="independently managed assurance contracts JSON")
        action.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info", "none"], default="high")
        action.add_argument("--json-out", type=Path, help="write JSON report to a new path (default: stdout)")
        action.add_argument("--sarif-out", type=Path, help="write SARIF report to a new path")
    args = parser.parse_args(argv)
    try:
        sources = ([args.snapshot] if args.command == "audit" else [args.baseline, args.candidate])
        if args.policy:
            sources.append(args.policy)
        destination_paths = [x for x in (args.json_out, args.sarif_out) if x is not None]
        if len({x.resolve(strict=False) for x in destination_paths}) < len(destination_paths):
            raise InputError("JSON and SARIF destinations must be distinct")
        if any(x.resolve(strict=False) == inp.resolve(strict=False) for x in destination_paths for inp in sources):
            raise InputError("an output path cannot replace an input")
        if any(x.exists() or x.is_symlink() for x in destination_paths):
            raise InputError("an output already exists; refusing all writes")
        contracts = parse_contracts(load(args.policy)) if args.policy else ()
        if args.command == "audit":
            findings = audit(parse(load(args.snapshot)), contracts)
            report = audit_report(findings, args.snapshot.name)
            candidate_findings = findings
            gate = findings
            target = args.snapshot.name
        else:
            before = audit(parse(load(args.baseline)), contracts)
            candidate_findings = audit(parse(load(args.candidate)), contracts)
            report = diff_report(before, candidate_findings, args.baseline.name, args.candidate.name)
            prior = {f.fingerprint for f in before}
            introduced = [f for f in candidate_findings if f.fingerprint not in prior]
            gate = candidate_findings if args.all_findings else introduced
            target = args.candidate.name
        if args.json_out:
            _write(args.json_out, _emit(report), sources)
        else:
            sys.stdout.write(_emit(report))
        if args.sarif_out:
            # SARIF represents current/introduced issues, never resolved ones.
            active = gate if args.command == "diff" and not args.all_findings else candidate_findings
            _write(args.sarif_out, _emit(sarif(active, target)), sources + ([args.json_out] if args.json_out else []))
        return 2 if _fail(gate, args.fail_on) else 0
    except InputError as exc:
        print(f"input/output error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
