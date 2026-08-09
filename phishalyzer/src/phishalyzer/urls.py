"""Analýza odkazů. Nikdy žádný odkaz nenačítáme — potvrdili bychom útočníkovi,
že adresa žije, a prozradili IP analytika. Výstup vždy defangovaný."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .findings import Finding, Severity
from .identity import registered_domain

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "s.id", "rebrand.ly",
    "1url.cz", "kr.cz",
}

# Značky pro kontrolu podobnosti domén (typosquatting, pomlčkové varianty).
BRAND_DOMAINS = {
    "csas.cz", "kb.cz", "csob.cz", "moneta.cz", "fio.cz", "airbank.cz",
    "ceskaposta.cz", "zasilkovna.cz", "microsoft.com", "google.com",
    "apple.com", "paypal.com", "amazon.com", "dhl.com", "dpd.com", "ppl.cz",
    "netflix.com", "facebook.com", "seznam.cz", "mojebanka.cz",
}


@dataclass
class LinkInfo:
    href: str
    text: str = ""
    source: str = "html"  # html | text

    @property
    def host(self) -> str:
        try:
            return (urlsplit(self.href).hostname or "").lower()
        except ValueError:
            return ""

    @property
    def domain(self) -> str:
        return registered_domain(self.host) if self.host else ""


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[LinkInfo] = []
        self._current: LinkInfo | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href") or ""
            self._current = LinkInfo(href=href.strip())
            self._text_parts = []

    def handle_data(self, data):
        if self._current is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current is not None:
            self._current.text = " ".join("".join(self._text_parts).split())
            if self._current.href.lower().startswith(("http://", "https://")):
                self.links.append(self._current)
            self._current = None


def extract_links(html_body: str, text_body: str) -> list[LinkInfo]:
    links: list[LinkInfo] = []
    if html_body:
        parser = _LinkExtractor()
        try:
            parser.feed(html_body)
        except Exception:
            pass
        links.extend(parser.links)
    if text_body:
        for m in URL_RE.finditer(text_body):
            links.append(LinkInfo(href=m.group(0).rstrip(".,;"), source="text"))
    return links


def defang(url: str) -> str:
    """hxxp://zlo[.]ru — aby na to nikdo v reportu neklikl."""
    out = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return out.replace(".", "[.]")


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _looks_like_brand(domain: str) -> str | None:
    """Vrátí napodobovanou značku, nebo None. Přesná shoda značku nevrací."""
    if domain in BRAND_DOMAINS:
        return None
    name = domain.rsplit(".", 1)[0]
    for brand_domain in BRAND_DOMAINS:
        brand_name = brand_domain.rsplit(".", 1)[0]
        if len(brand_name) < 3:
            continue  # kb.cz apod. — příliš krátké na smysluplnou vzdálenost
        # pomlčkové varianty: mojebanka-zabezpeceni.cz
        parts = re.split(r"[-.]", name)
        if brand_name in parts and domain != brand_domain:
            return brand_domain
        if _levenshtein(name, brand_name) == 1:
            return brand_domain
    return None


def analyze_urls(html_body: str, text_body: str) -> tuple[list[Finding], list[LinkInfo]]:
    findings: list[Finding] = []
    links = extract_links(html_body, text_body)
    seen: set[str] = set()

    for link in links:
        domain = link.domain
        if not domain:
            continue

        # text odkazu obsahuje doménu, href míří jinam
        if link.text:
            m = re.search(r"\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b",
                          link.text.lower())
            if m:
                text_domain = registered_domain(m.group(1))
                if text_domain and text_domain != domain:
                    findings.append(Finding(
                        id="link_text_mismatch",
                        severity=Severity.HIGH,
                        title="Text odkazu nesouhlasí se skutečným cílem",
                        evidence={"text": link.text, "target": defang(link.href),
                                  "text_domain": text_domain,
                                  "target_domain": defang(domain)},
                        explanation=(
                            "Uživatel vidí v textu jednu doménu, odkaz ale míří "
                            "jinam. Samo o sobě silný signál."
                        ),
                    ))

        key_punycode = f"punycode:{domain}"
        if "xn--" in link.host and key_punycode not in seen:
            seen.add(key_punycode)
            findings.append(Finding(
                id="punycode_domain",
                severity=Severity.HIGH,
                title="Doména používá punycode (xn--)",
                evidence={"url": defang(link.href), "host": defang(link.host)},
                explanation=(
                    "Punycode umožňuje znaky, které jen vypadají jako latinka "
                    "(homoglyfy). Časté u napodobenin známých domén."
                ),
            ))

        try:
            link.href.encode("ascii")
        except UnicodeEncodeError:
            key = f"nonascii:{domain}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    id="non_ascii_url",
                    severity=Severity.MEDIUM,
                    title="Odkaz obsahuje ne-ASCII znaky",
                    evidence={"url": defang(link.href)},
                    explanation="Možné homoglyfy — znaky vypadající jako latinka.",
                ))

        if domain in SHORTENERS:
            key = f"shortener:{domain}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    id="url_shortener",
                    severity=Severity.MEDIUM,
                    title="Odkaz vede přes zkracovač",
                    evidence={"url": defang(link.href), "service": domain},
                    explanation=(
                        "Zkracovač skrývá skutečný cíl. Bez načtení (které "
                        "neděláme) nejde ověřit, kam vede."
                    ),
                ))

        imitated = _looks_like_brand(domain)
        if imitated:
            key = f"lookalike:{domain}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    id="brand_lookalike_domain",
                    severity=Severity.HIGH,
                    title="Doména napodobuje známou značku",
                    evidence={"domain": defang(domain),
                              "imitates": imitated,
                              "url": defang(link.href)},
                    explanation=(
                        "Doména se liší o jeden znak nebo přidává slova pomlčkou "
                        "(např. mojebanka-zabezpeceni). Uživatel rozdíl snadno "
                        "přehlédne."
                    ),
                ))

    return findings, links
