import hashlib
from collections import Counter, defaultdict
from .models import Finding, Flow


def _id(rule: str, evidence: list[Flow]) -> str:
    material = rule + "|" + "|".join(sorted(f.flow_id for f in evidence))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _severity(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 70: return "High"
    if score >= 45: return "Medium"
    return "Low"


def _make(rule, title, entity, evidence, score, attack, rationale, remediation, validation):
    return Finding(_id(rule, evidence), title, _severity(score), score, entity,
                   tuple(f.flow_id for f in evidence), tuple(attack), rationale, remediation, validation)


def analyze(flows: list[Flow]) -> list[Finding]:
    out: list[Finding] = []
    by_src: dict[str, list[Flow]] = defaultdict(list)
    for f in sorted(flows, key=lambda x: x.timestamp):
        by_src[f.src_asset].append(f)

    for src, rows in by_src.items():
        sensitive = [f for f in rows if f.dst_zone in {"database", "management", "backup"} and not f.approved]
        if sensitive:
            out.append(_make("sensitive-zone", "Unapproved access to sensitive internal zone", src, sensitive,
                82, ("T1021", "T1210"), "The source communicated with a sensitive internal zone without an approved-flow marker.",
                "Validate business need, restrict policy to explicit sources/services and document an owner-approved exception where required.",
                "Re-test the intended application path and confirm unapproved source-to-zone traffic is denied."))

        admin = [f for f in rows if f.dst_port in {22, 3389, 5985, 5986} and f.dst_zone in {"server", "management"} and not f.approved]
        if len({f.dst_asset for f in admin}) >= 3:
            out.append(_make("admin-fanout", "Administrative-protocol fan-out across internal assets", src, admin,
                88, ("T1021", "T1078"), "One source reached multiple internal systems over administrative service ports without approved-flow context.",
                "Validate the source identity and management role, constrain administrative paths and review authentication telemetry.",
                "Confirm only approved management hosts can reach the affected services."))

        cross_zone = [f for f in rows if f.src_zone == "user" and f.dst_zone == "database" and not f.approved]
        if cross_zone:
            out.append(_make("user-db", "Direct user-zone to database-zone communication", src, cross_zone,
                76, ("T1210",), "Direct user-to-database traffic can bypass intended application-tier segmentation.",
                "Require access through approved application/service tiers unless a documented exception exists.",
                "Verify user-zone clients cannot directly reach database listeners after remediation."))

        bulk = [f for f in rows if f.bytes_out >= 50_000_000 and f.dst_zone not in {"backup"} and not f.approved]
        if bulk:
            out.append(_make("bulk-eastwest", "Unapproved high-volume internal transfer", src, bulk,
                68, ("T1041",), "A high-volume east-west transfer occurred outside the approved backup zone.",
                "Validate workload purpose and data classification; restrict unnecessary peer-to-peer transfer paths.",
                "Confirm expected transfer paths remain functional and the unapproved path is removed or formally approved."))

    return sorted(out, key=lambda x: x.score, reverse=True)


def metrics(findings: list[Finding]) -> dict:
    c = Counter(f.severity for f in findings)
    return {"findings": len(findings), "critical_high": c["Critical"] + c["High"],
            "highest_score": max((f.score for f in findings), default=0),
            "affected_sources": len({f.entity for f in findings}), "severity_counts": dict(c)}
