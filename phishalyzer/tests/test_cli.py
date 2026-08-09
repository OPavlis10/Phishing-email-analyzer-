import json
from pathlib import Path

from phishalyzer.cli import analyze, main

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_legitimate():
    report = analyze(str(FIXTURES / "legitimate.eml"))
    assert report["verdict"] == "clean"


def test_analyze_spoof_is_not_clean():
    report = analyze(str(FIXTURES / "display_name_spoof.eml"))
    assert report["verdict"] in ("suspicious", "malicious")


def test_analyze_double_extension_malicious():
    report = analyze(str(FIXTURES / "double_extension.eml"))
    assert report["verdict"] == "malicious"


def test_urls_are_defanged_in_report():
    report = analyze(str(FIXTURES / "link_text_mismatch.eml"))
    dumped = json.dumps(report)
    assert "hxxp" in dumped
    assert "http://zlo" not in dumped


def test_cli_json_and_exit_codes(capsys):
    code = main([str(FIXTURES / "legitimate.eml"), "--json"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "clean"

    code = main([str(FIXTURES / "double_extension.eml")])
    assert code == 1
