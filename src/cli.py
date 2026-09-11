import argparse
from pathlib import Path
from .analyzer import analyze
from .io import load_flows
from .reporting import markdown_report


def main():
    p = argparse.ArgumentParser(description="Analyze supplied east-west network-flow metadata offline")
    p.add_argument("input")
    p.add_argument("--output", default="east-west-assessment.md")
    a = p.parse_args()
    findings = analyze(load_flows(a.input))
    Path(a.output).write_text(markdown_report(findings), encoding="utf-8")
    print(f"Wrote {a.output} with {len(findings)} findings")


if __name__ == "__main__":
    main()
