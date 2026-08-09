from phishalyzer.identity import analyze_identity, registered_domain


def ids(findings):
    return {f.id for f in findings}


def test_registered_domain():
    assert registered_domain("mail.firma.cz") == "firma.cz"
    assert registered_domain("uzivatel@sub.firma.co.uk") == "firma.co.uk"
    assert registered_domain("firma.cz") == "firma.cz"


def test_legitimate_is_quiet(load):
    findings = analyze_identity(load("legitimate.eml").message)
    assert ids(findings) == set()


def test_return_path_mismatch(load):
    findings = analyze_identity(load("return_path_mismatch.eml").message)
    assert "return_path_mismatch" in ids(findings)


def test_reply_to_mismatch(load):
    findings = analyze_identity(load("reply_to_mismatch.eml").message)
    assert "reply_to_mismatch" in ids(findings)


def test_display_name_spoof_passes_auth_but_flagged(load):
    findings = analyze_identity(load("display_name_spoof.eml").message)
    assert "display_name_brand_spoof" in ids(findings)
    # autentizace prošla — spoof přes freemail projde SPF/DKIM/DMARC
    assert "spf_fail" not in ids(findings)


def test_encoded_display_name_brand(load):
    findings = analyze_identity(load("display_name_encoded.eml").message)
    assert "display_name_brand_spoof" in ids(findings)


def test_multiple_from(load):
    findings = analyze_identity(load("multiple_from.eml").message)
    assert "multiple_from" in ids(findings)
