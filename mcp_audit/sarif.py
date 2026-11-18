"""SARIF 2.1.0 so findings land in GitHub code scanning."""
from __future__ import annotations

from . import __version__
from .model import Finding
from .rules import RULES

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub reads security-severity from the rule descriptor, so each rule carries its typical severity
RULE_SEVERITY = {"MA001": "critical", "MA002": "high", "MA003": "high", "MA004": "high", "MA005": "medium", "MA006": "low",
                 "MA007": "high", "MA008": "high", "MA009": "medium", "MA010": "high", "MA011": "medium", "MA012": "high", "MA013": "high"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def to_sarif(findings: list[Finding], artifact: str = "mcp.json") -> dict:
    rules = [{
        "id": r.id, "name": r.name,
        "shortDescription": {"text": r.name.replace("-", " ")},
        "fullDescription": {"text": r.summary},
        "helpUri": f"https://github.com/Sebastianrodaaa/mcp-audit#{r.id.lower()}",
        "defaultConfiguration": {"level": LEVEL[RULE_SEVERITY[r.id]]},
        "properties": {"tags": ["security", "mcp", "tool-poisoning"], "security-severity": SCORE[RULE_SEVERITY[r.id]]},
    } for r in RULES.values()]
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule,
            "level": LEVEL[f.severity],
            "message": {"text": f"[{f.server}] {f.kind} `{f.item}`: {f.message}" + (f"\nEvidence: {f.evidence}" if f.evidence else "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": artifact}, "region": {"startLine": 1}},
                "logicalLocations": [{"name": f.item, "fullyQualifiedName": f"{f.server}/{f.kind}/{f.item}#{f.field}", "kind": f.kind}],
            }],
            "partialFingerprints": {"mcpAudit/v1": f"{f.server}/{f.kind}/{f.item}/{f.rule}/{f.field}"},
            "properties": {"severity": f.severity, "security-severity": SCORE[f.severity], "server": f.server},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mcp-audit", "version": __version__,
                                      "informationUri": "https://github.com/Sebastianrodaaa/mcp-audit", "rules": rules}},
                  "results": results}],
    }
