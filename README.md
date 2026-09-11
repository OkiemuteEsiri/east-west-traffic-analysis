# East-West Traffic Analysis

A defensive Network Security and Detection Engineering project for evaluating internal network-flow metadata, segmentation boundaries and lateral-movement indicators.

The implementation is intentionally **offline**. It analyzes synthetic flow records only and performs no packet capture, scanning, credential use, active probing or traffic generation.

## Problem statement
Many organizations have strong north-south perimeter controls while internal east-west visibility remains weaker. That creates blind spots around lateral movement, management-plane access, direct user-to-database communication and large internal data transfers. This project demonstrates a structured way to normalize internal flow evidence, correlate behavior by source asset and turn it into explainable remediation decisions.

## Architecture

```text
Synthetic flow metadata
        |
        v
Fail-closed ingestion
        |
        v
Validated Flow model
        |
        v
Source-centric correlation
        |
        v
Risk + ATT&CK context
        |
        v
Prioritized finding
        |
        v
Remediation / revalidation report
```

## Implemented analytics
- Unapproved communication into sensitive database, management or backup zones.
- Administrative-protocol fan-out across multiple internal hosts.
- Direct user-zone to database-zone communication.
- Large east-west transfers outside approved backup paths.
- Deterministic evidence-linked finding IDs.
- Portfolio metrics for severity, affected sources and highest risk.

## Important design decision
Traffic is not classified as malicious simply because it crosses zones or uses an administrative protocol. The engine relies on synthetic `approved` context and architecture assumptions. In production, those decisions should come from service ownership, application dependency maps, change control and authoritative flow policy.

## ATT&CK context
Current defensive mappings include **T1021 Remote Services**, **T1078 Valid Accounts**, **T1210 Exploitation of Remote Services** and **T1041 Exfiltration Over C2 Channel**. ATT&CK mapping provides investigation context only and is not proof that compromise, exploitation or exfiltration occurred.

## Repository structure

```text
src/
  models.py
  analyzer.py
  io.py
  reporting.py
  cli.py
data/
  synthetic_flows.json
tests/
  test_analyzer.py
docs/
  methodology.md
reports/
  example-assessment.md
.github/workflows/
  ci.yml
```

## Run locally
Python 3.12+ with no third-party dependencies.

```bash
python -m src.cli data/synthetic_flows.json --output east-west-assessment.md
python -m unittest discover -s tests -v
```

## Engineering controls
The loader rejects malformed top-level input, unsupported zones, invalid ports, negative byte counts and duplicate flow IDs. Timestamps must be timezone-aware. Findings include evidence IDs, rationale, remediation guidance and explicit post-change validation criteria.

## Remediation lifecycle
`observe -> validate business context -> compare with approved flow model -> prioritize -> change segmentation policy -> test blocked path -> test legitimate path -> retain closure evidence`

A segmentation change is not considered complete unless both negative and positive validation succeed: the undesired path is blocked while approved application/service traffic still works.

## Skills demonstrated
Network security, segmentation assurance, detection engineering, Python security automation, traffic analysis, ATT&CK mapping, risk communication, evidence governance, remediation validation, unit testing and CI/CD.

## CI
GitHub Actions compiles the Python package, runs ten unit tests and performs an offline CLI smoke test with read-only repository permissions.

## Limitations and safety
This is not a live network-monitoring or exploitation tool. It does not capture packets, enumerate hosts, scan services, use credentials, perform lateral movement, exploit remote services or target production systems. All bundled assets and flows are synthetic.

## Roadmap
- Add configurable approved-flow matrices.
- Add time-window and recurrence analytics.
- Add source/destination baseline comparison.
- Add service-owner and asset-criticality context.
- Add JSON/CSV findings export.
- Add before/after segmentation validation reporting.
