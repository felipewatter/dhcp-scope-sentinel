"""Deterministic JSON and SARIF 2.1.0 reports with stable finding fingerprints."""
from __future__ import annotations

from collections import Counter
from typing import Any

from . import __version__
from .engine import Finding, RULES


def summarize(findings: list[Finding]) -> dict[str, int]:
    levels = Counter(item.severity for item in findings)
    return {severity: levels.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")}


def audit_report(findings: list[Finding], snapshot: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "tool": "DHCP ScopeSentinel", "mode": "audit",
            "snapshot": snapshot, "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings]}


def diff_report(old: list[Finding], new: list[Finding], baseline: str, candidate: str) -> dict[str, Any]:
    before = {f.fingerprint: f for f in old}
    after = {f.fingerprint: f for f in new}
    new_issues = [f for f in new if f.fingerprint not in before]
    persisting = [f for f in new if f.fingerprint in before]
    resolved = [f for f in old if f.fingerprint not in after]
    return {"schemaVersion": 1, "tool": "DHCP ScopeSentinel", "mode": "diff",
            "baseline": baseline, "candidate": candidate,
            "summary": {"introduced": summarize(new_issues), "persistent": summarize(persisting), "resolved": summarize(resolved)},
            "introduced": [x.to_dict() for x in new_issues],
            "persistent": [x.to_dict() for x in persisting],
            "resolved": [x.to_dict() for x in resolved]}


def sarif(findings: list[Finding], artifact: str) -> dict[str, Any]:
    active = sorted({x.rule for x in findings})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "DHCP ScopeSentinel", "semanticVersion": __version__,
                    "informationUri": "https://github.com/felipewatter/dhcp-scope-sentinel",
                    "rules": [{"id": key, "name": RULES[key][1],
                               "shortDescription": {"text": RULES[key][1]},
                               "properties": {"security-severity": RULES[key][0]}} for key in active]}},
                      "results": [{"ruleId": f.rule,
                                   "level": "error" if f.severity in ("high", "critical") else "warning" if f.severity == "medium" else "note",
                                   "message": {"text": f"[{f.segment}] {f.subject}: {f.detail}"},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact}}}],
                                   "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
                                   "properties": {"severity": f.severity, "segment": f.segment}}
                                  for f in findings]}]}
