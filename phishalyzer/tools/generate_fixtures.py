"""Generátor syntetických .eml fixtures do tests/fixtures/.

Do repozitáře nikdy nepatří skutečné phishing maily — jsou v nich adresy
živých lidí a malware. Syntetické vzorky testují přesně to, co mají.

Spuštění: python tools/generate_fixtures.py
"""

from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from email.policy import default
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _base(from_: str, subject: str, body: str) -> EmailMessage:
    msg = EmailMessage(policy=default)
    msg["From"] = from_
    msg["To"] = "prijemce@example.com"
    msg["Subject"] = subject
    msg["Date"] = "Mon, 05 Jan 2026 09:15:00 +0100"
    msg["Message-ID"] = "<test@example.com>"
    msg["Received"] = (
        "from mail.example.net (mail.example.net [203.0.113.5]) "
        "by mx.example.com; Mon, 05 Jan 2026 09:15:02 +0100"
    )
    msg.set_content(body)
    return msg


def legitimate() -> EmailMessage:
    msg = _base("Jan Novák <jan.novak@example.com>", "Zápis z porady",
                "Ahoj, v příloze posílám zápis. Jan")
    msg["Return-Path"] = "<jan.novak@example.com>"
    msg["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    )
    return msg


def return_path_mismatch() -> EmailMessage:
    msg = _base("Fakturace <fakturace@duveryhodna-firma.example>",
                "Neuhrazená faktura", "Uhraďte prosím fakturu v příloze.")
    msg["Return-Path"] = "<bounce@uplne-jina-domena.example>"
    return msg


def reply_to_mismatch() -> EmailMessage:
    msg = _base("Ředitel <reditel@firma.example>", "Urgentní platba",
                "Potřebuji okamžitě provést platbu. Odpověz na tento mail.")
    msg["Return-Path"] = "<reditel@firma.example>"
    msg["Reply-To"] = "reditel.firma@gmail.com"
    return msg


def display_name_spoof() -> EmailMessage:
    msg = _base('"Česká spořitelna" <nahodny.ucet1234@gmail.com>',
                "Vaše platba byla pozastavena",
                "Přihlaste se a ověřte údaje.")
    msg["Return-Path"] = "<nahodny.ucet1234@gmail.com>"
    msg["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
        "dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com"
    )
    return msg


def display_name_encoded() -> EmailMessage:
    # =?utf-8?B?...?= => "Komerční banka" — dekódování hlaviček
    msg = _base("=?utf-8?B?S29tZXLEjW7DrSBiYW5rYQ==?= <podpora@banka-overeni.example>",
                "Ověření účtu", "Klikněte na odkaz níže.")
    return msg


def link_text_mismatch() -> EmailMessage:
    msg = _base("Podpora <podpora@example.org>", "Obnovte si heslo",
                "Obnovte si heslo na www.csas.cz")
    msg.add_alternative(
        '<html><body><p>Obnovte si heslo na '
        '<a href="http://zlo.example.ru/login">www.csas.cz</a></p>'
        "</body></html>",
        subtype="html",
    )
    return msg


def punycode_link() -> EmailMessage:
    msg = _base("Info <info@example.org>", "Doručení zásilky",
                "Sledujte zásilku.")
    msg.add_alternative(
        '<html><body><a href="http://xn--seznm-3ta.example/track">'
        "Sledovat zásilku</a></body></html>",
        subtype="html",
    )
    return msg


def shortener_and_lookalike() -> EmailMessage:
    msg = _base("Bezpečnost <security@example.org>", "Nutné ověření",
                "Ověřte účet: https://bit.ly/abc123")
    msg.add_alternative(
        '<html><body><a href="https://mojebanka-zabezpeceni.example/verify">'
        "Ověřit účet</a></body></html>",
        subtype="html",
    )
    return msg


def double_extension() -> EmailMessage:
    msg = _base("Účtárna <uctarna@example.org>", "Faktura 2026-001",
                "Faktura v příloze.")
    msg["Return-Path"] = "<uctarna@example.org>"
    # PE hlavička MZ — obsah je exe, jméno tvrdí pdf
    msg.add_attachment(b"MZ\x90\x00" + b"\x00" * 60,
                       maintype="application", subtype="octet-stream",
                       filename="faktura.pdf.exe")
    return msg


def macro_attachment() -> EmailMessage:
    msg = _base("HR <hr@example.org>", "Nový formulář",
                "Vyplňte přiložený formulář.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/vbaProject.bin", "fake")
    msg.add_attachment(buf.getvalue(), maintype="application",
                       subtype="vnd.ms-word.document.macroEnabled.12",
                       filename="formular.docm")
    return msg


def password_zip() -> EmailMessage:
    msg = _base("Doprava <doprava@example.org>", "Dokumenty k zásilce",
                "Heslo k archivu je: 1234")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dokument.exe", "MZ fake")
        # ručně nastavíme flag bit šifrování u položky
    data = bytearray(buf.getvalue())
    # nastav encryption flag bit v local file header (offset 6) a central dir
    idx = data.find(b"PK\x03\x04")
    if idx != -1:
        data[idx + 6] |= 0x01
    idx = data.find(b"PK\x01\x02")
    if idx != -1:
        data[idx + 8] |= 0x01
    msg.add_attachment(bytes(data), maintype="application", subtype="zip",
                       filename="dokumenty.zip")
    return msg


def multiple_from() -> EmailMessage:
    msg = _base("Podpora <podpora@example.com>", "Aktualizace účtu",
                "Klikněte pro aktualizaci.")
    # druhá hlavička From — obejití kontrol
    msg._headers.append(("From", "Admin <admin@zlo.example>"))  # noqa: SLF001
    return msg


SAMPLES = {
    "legitimate.eml": legitimate,
    "return_path_mismatch.eml": return_path_mismatch,
    "reply_to_mismatch.eml": reply_to_mismatch,
    "display_name_spoof.eml": display_name_spoof,
    "display_name_encoded.eml": display_name_encoded,
    "link_text_mismatch.eml": link_text_mismatch,
    "punycode_link.eml": punycode_link,
    "shortener_and_lookalike.eml": shortener_and_lookalike,
    "double_extension.eml": double_extension,
    "macro_attachment.eml": macro_attachment,
    "password_zip.eml": password_zip,
    "multiple_from.eml": multiple_from,
}


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, factory in SAMPLES.items():
        path = FIXTURES / name
        path.write_bytes(factory().as_bytes())
        print(f"OK {path.relative_to(FIXTURES.parent.parent)}")


if __name__ == "__main__":
    main()
