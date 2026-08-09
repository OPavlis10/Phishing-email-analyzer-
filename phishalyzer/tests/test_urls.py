from phishalyzer.urls import analyze_urls, defang, extract_links


def ids(findings):
    return {f.id for f in findings}


def run(parsed):
    return analyze_urls(parsed.html_body, parsed.text_body)


def test_defang():
    assert defang("http://zlo.ru/a") == "hxxp://zlo[.]ru/a"
    assert defang("https://a.b.c/x.y") == "hxxps://a[.]b[.]c/x[.]y"


def test_link_text_mismatch(load):
    findings, links = run(load("link_text_mismatch.eml"))
    assert "link_text_mismatch" in ids(findings)
    assert any(l.source == "html" for l in links)


def test_punycode(load):
    findings, _ = run(load("punycode_link.eml"))
    assert "punycode_domain" in ids(findings)


def test_shortener_and_lookalike(load):
    findings, _ = run(load("shortener_and_lookalike.eml"))
    assert "url_shortener" in ids(findings)
    assert "brand_lookalike_domain" in ids(findings)


def test_legitimate_no_url_findings(load):
    findings, _ = run(load("legitimate.eml"))
    assert ids(findings) == set()


def test_extract_from_both_parts(load):
    parsed = load("shortener_and_lookalike.eml")
    links = extract_links(parsed.html_body, parsed.text_body)
    sources = {l.source for l in links}
    assert sources == {"html", "text"}
