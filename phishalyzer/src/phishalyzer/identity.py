"""Identita odesílatele: From, Return-Path, Reply-To, display name, autentizace.

Vše offline. Authentication-Results jen čteme (authres), vlastní SPF/DKIM
ověřování sem nepatří — vnášelo by živou závislost na DNS.
"""

from __future__ import annotations

import re
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

import authres
import tldextract

from .findings import Finding, Severity

# Offline extraktor — jen zabalený snapshot PSL, žádné stahování.
_extract = tldextract.TLDExtract(suffix_list_urls=())

# Značky nejčastěji zneužívané v display name. Rozšiřitelné.
KNOWN_BRANDS: dict[str, list[str]] = {
    "česká spořitelna": ["csas.cz", "ceskasporitelna.cz"],
    "ceska sporitelna": ["csas.cz", "ceskasporitelna.cz"],
    "komerční banka": ["kb.cz"],
    "komercni banka": ["kb.cz"],
    "čsob": ["csob.cz"],
    "csob": ["csob.cz"],
    "moneta": ["moneta.cz"],
    "fio banka": ["fio.cz"],
    "airbank": ["airbank.cz"],
    "česká pošta": ["ceskaposta.cz"],
    "ceska posta": ["ceskaposta.cz"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com", "paypal.cz"],
    "amazon": ["amazon.com", "amazon.de"],
    "dhl": ["dhl.com", "dhl.cz", "dhl.de"],
    "dpd": ["dpd.com", "dpd.cz"],
    "ppl": ["ppl.cz"],
    "zásilkovna": ["zasilkovna.cz", "packeta.com"],
    "zasilkovna": ["zasilkovna.cz", "packeta.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
}

_FREEMAIL = {
    "gmail.com", "seznam.cz", "email.cz", "centrum.cz", "outlook.com",
    "hotmail.com", "yahoo.com", "protonmail.com", "proton.me", "icloud.com",
}

_DOMAIN_IN_TEXT = re.compile(r"\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", re.IGNORECASE)


def registered_domain(address_or_host: str) -> str:
    """`mail.firma.cz` -> `firma.cz`. Prázdný řetězec, když nejde určit."""
    host = address_or_host.rsplit("@", 1)[-1].strip().strip("<>").lower()
    ext = _extract(host)
    return ext.top_domain_under_public_suffix or host


def _addr(value: str | None) -> tuple[str, str]:
    """(display name, adresa) — dekódované, malými písmeny u adresy."""
    if not value:
        return "", ""
    name, addr = parseaddr(str(value))
    return name.strip(), addr.strip().lower()


def analyze_identity(msg: EmailMessage) -> list[Finding]:
    findings: list[Finding] = []

    from_values = msg.get_all("From", [])
    from_name, from_addr = _addr(from_values[0] if from_values else None)
    from_domain = registered_domain(from_addr) if from_addr else ""

    # --- vícenásobný From ---
    if len(from_values) > 1:
        findings.append(Finding(
            id="multiple_from",
            severity=Severity.CRITICAL,
            title="E-mail obsahuje více hlaviček From",
            evidence={"from_headers": [str(v) for v in from_values]},
            explanation=(
                "Klient zobrazí jednu hlavičku, kontroly vyhodnotí druhou. "
                "Legitimní pošta má hlavičku From vždy jen jednu."
            ),
        ))

    # --- From vs Return-Path ---
    _, return_path = _addr(msg.get("Return-Path"))
    if from_addr and return_path:
        rp_domain = registered_domain(return_path)
        if rp_domain and from_domain and rp_domain != from_domain:
            findings.append(Finding(
                id="return_path_mismatch",
                severity=Severity.MEDIUM,
                title="Return-Path míří na jinou doménu než From",
                evidence={"from": from_addr, "return_path": return_path},
                explanation=(
                    "Obálková adresa (skutečný odesílatel na úrovni SMTP) je z jiné "
                    "domény než zobrazená hlavička From. Bývá to legitimní u "
                    "mailingových služeb, ale u běžné korespondence je to podezřelé."
                ),
            ))

    # --- From vs Reply-To ---
    reply_to_all = getaddresses(msg.get_all("Reply-To", []))
    for _, reply_addr in reply_to_all:
        reply_addr = reply_addr.strip().lower()
        if not reply_addr or not from_addr:
            continue
        if registered_domain(reply_addr) != from_domain:
            findings.append(Finding(
                id="reply_to_mismatch",
                severity=Severity.HIGH,
                title="Reply-To míří na jinou doménu než From",
                evidence={"from": from_addr, "reply_to": reply_addr},
                explanation=(
                    "Odpověď nepůjde odesílateli, ale na cizí schránku. "
                    "Klasika u firemního podvodu: jméno ředitele, odpověď na freemail."
                ),
            ))
            break

    # --- display name vs adresa ---
    findings.extend(_check_display_name(from_name, from_addr, from_domain))

    # --- Authentication-Results ---
    findings.extend(_check_auth_results(msg))

    return findings


def _check_display_name(name: str, addr: str, addr_domain: str) -> list[Finding]:
    findings: list[Finding] = []
    if not name or not addr:
        return findings
    name_lower = name.lower()

    # doména napsaná v display name, která nesouhlasí se skutečnou adresou
    for m in _DOMAIN_IN_TEXT.finditer(name_lower):
        claimed = registered_domain(m.group(1))
        if claimed and claimed != addr_domain:
            findings.append(Finding(
                id="display_name_domain_mismatch",
                severity=Severity.HIGH,
                title="Display name obsahuje jinou doménu, než odkud mail přišel",
                evidence={"display_name": name, "address": addr,
                          "claimed_domain": claimed, "actual_domain": addr_domain},
                explanation=(
                    "Jméno odesílatele tvrdí jinou doménu, než ze které mail "
                    "skutečně přišel. Uživatel často vidí jen display name."
                ),
            ))
            break

    # název známé značky v display name, adresa ale z cizí domény
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in name_lower and addr_domain not in legit_domains:
            severity = Severity.HIGH if addr_domain in _FREEMAIL else Severity.MEDIUM
            findings.append(Finding(
                id="display_name_brand_spoof",
                severity=severity,
                title=f"Display name se vydává za značku, adresa tomu neodpovídá",
                evidence={"display_name": name, "address": addr,
                          "brand": brand, "expected_domains": legit_domains},
                explanation=(
                    "Největší reálná kategorie phishingu: útočník adresu skutečně "
                    "vlastní, takže projde SPF i DKIM. Autentizace ověřuje "
                    "identitu domény, ne úmysl."
                ),
            ))
            break

    return findings


def _check_auth_results(msg: EmailMessage) -> list[Finding]:
    """Čte jen první (nejvrchnější) Authentication-Results — tu přidal server,
    který mail doručil. Hlavičky níže mohl vložit kdokoli po cestě."""
    findings: list[Finding] = []
    values = msg.get_all("Authentication-Results", [])
    if not values:
        findings.append(Finding(
            id="auth_results_missing",
            severity=Severity.INFO,
            title="Chybí hlavička Authentication-Results",
            evidence={},
            explanation=(
                "Přijímající server výsledky SPF/DKIM/DMARC nezapsal, nebo jde "
                "o mail získaný jinak než doručením (např. export z odesílatele)."
            ),
        ))
        return findings

    try:
        parsed = authres.AuthenticationResultsHeader.parse(
            "Authentication-Results: " + str(values[0])
        )
    except Exception as exc:
        findings.append(Finding(
            id="auth_results_unparseable",
            severity=Severity.LOW,
            title="Authentication-Results nejde rozparsovat",
            evidence={"header": str(values[0]), "error": str(exc)},
            explanation="Nestandardní formát hlavičky.",
        ))
        return findings

    results = {r.method: r.result for r in parsed.results}
    severity_map = {"dmarc": Severity.HIGH, "dkim": Severity.MEDIUM, "spf": Severity.MEDIUM}
    for method in ("spf", "dkim", "dmarc"):
        result = results.get(method)
        if result in ("fail", "permerror"):
            findings.append(Finding(
                id=f"{method}_fail",
                severity=severity_map[method],
                title=f"{method.upper()} selhal ({result})",
                evidence={"method": method, "result": result,
                          "header": str(values[0])},
                explanation=(
                    f"Přijímající server vyhodnotil {method.upper()} jako {result}. "
                    "Pozor na opačný závěr: pass znamená jen, že odesílatel doménu "
                    "vlastní, ne že je mail legitimní."
                ),
            ))
    return findings


def received_timeline(hops) -> list[dict]:
    """Received chain jako časová osa pro ruční posouzení. Není to signál —
    legitimní pošta přes forwardery vypadá stejně divně."""
    return [hop.to_dict() for hop in hops]
