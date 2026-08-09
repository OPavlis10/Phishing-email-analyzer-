"""CLI: JSON jako primární výstup, lidsky čitelný text jako druhý."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .attachments import analyze_attachments
from .findings import Finding, Severity
from .identity import analyze_identity, received_timeline
from .parser import ParseError, parse_file
from .urls import analyze_urls, defang
from .verdict import compute_verdict


def analyze(path: str) -> dict:
    parsed = parse_file(path)
    msg = parsed.message

    findings: list[Finding] = []
    findings.extend(analyze_identity(msg))
    url_findings, links = analyze_urls(parsed.html_body, parsed.text_body)
    findings.extend(url_findings)
    att_findings, attachments = analyze_attachments(parsed.attachments)
    findings.extend(att_findings)

    return {
        "phishalyzer_version": __version__,
        "verdict": compute_verdict(findings),
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "date": str(msg.get("Date", "")),
        "findings": [f.to_dict() for f in sorted(
            findings, key=lambda f: f.severity, reverse=True)],
        "links": [{"url": defang(l.href), "text": l.text, "source": l.source}
                  for l in links],
        "attachments": [a.to_dict() for a in attachments],
        "received_timeline": received_timeline(parsed.received_chain),
    }


_SEVERITY_MARK = {
    "critical": "[!!]", "high": "[! ]", "medium": "[~ ]",
    "low": "[. ]", "info": "[i ]",
}


def _print_text(report: dict) -> None:
    print(f"phishalyzer {report['phishalyzer_version']}")
    print(f"Předmět:  {report['subject']}")
    print(f"Od:       {report['from']}")
    print(f"Datum:    {report['date']}")
    print(f"\nVERDIKT:  {report['verdict'].upper()}\n")

    if report["findings"]:
        print("Nálezy:")
        for f in report["findings"]:
            mark = _SEVERITY_MARK.get(f["severity"], "[? ]")
            print(f"  {mark} {f['title']}  ({f['id']})")
            for k, v in f["evidence"].items():
                print(f"        {k}: {v}")
            if f["explanation"]:
                print(f"        -> {f['explanation']}")
    else:
        print("Žádné nálezy.")

    if report["links"]:
        print("\nOdkazy (defangované):")
        for link in report["links"]:
            text = f"  text: {link['text']}" if link["text"] else ""
            print(f"  {link['url']}{text}")

    if report["attachments"]:
        print("\nPřílohy:")
        for a in report["attachments"]:
            print(f"  {a['filename']}  {a['size']} B  {a['detected_type'] or '?'}")
            print(f"    sha256: {a['sha256']}")

    if report["received_timeline"]:
        print("\nReceived (časová osa, jen pro ruční posouzení):")
        for hop in reversed(report["received_timeline"]):
            print(f"  {hop['timestamp'] or '?':<40} "
                  f"{hop['from'] or '?'} -> {hop['by'] or '?'}"
                  f"{'  [' + hop['ip'] + ']' if hop['ip'] else ''}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="phishalyzer",
        description="Offline analýza .eml souboru. Nikdy nesahá na síť.",
    )
    ap.add_argument("eml", help="cesta k .eml souboru")
    ap.add_argument("--json", action="store_true", help="výstup jako JSON")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        report = analyze(args.eml)
    except (ParseError, OSError) as exc:
        print(f"Chyba: {exc}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        _print_text(report)

    return {"clean": 0, "suspicious": 1, "malicious": 1}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
