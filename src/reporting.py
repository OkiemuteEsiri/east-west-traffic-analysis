from .analyzer import metrics
from .models import Finding


def markdown_report(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = ["# East-West Traffic Analysis", "", "> Synthetic offline network-flow assessment. No packets were captured and no live network was scanned.", "",
             "## Executive metrics", "", f"- Findings: **{m['findings']}**", f"- Critical/High: **{m['critical_high']}**", f"- Highest score: **{m['highest_score']}/100**", f"- Affected sources: **{m['affected_sources']}**", "", "## Prioritized findings", ""]
    for f in findings:
        lines += [f"### {f.severity} — {f.title}", "", f"- Source: `{f.entity}`", f"- Score: **{f.score}/100**", f"- Evidence: {', '.join(f.evidence_ids)}", f"- ATT&CK context: {', '.join(f.attack)}", "", f"**Rationale:** {f.rationale}", "", f"**Remediation:** {f.remediation}", "", f"**Validation:** {f.validation}", ""]
    return "\n".join(lines)
