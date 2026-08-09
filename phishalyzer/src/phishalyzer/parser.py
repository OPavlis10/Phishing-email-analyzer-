"""Parsování .eml — nepřátelský vstup, proto limity na velikost a hloubku MIME.

Nikdy policy=compat32; policy.default dekóduje =?utf-8?B?...?= hlavičky.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_MIME_DEPTH = 20


class ParseError(Exception):
    pass


@dataclass
class ReceivedHop:
    """Jeden záznam Received — jen pro zobrazení, ne pro signál."""

    raw: str
    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict:
        return {
            "from": self.from_host,
            "by": self.by_host,
            "ip": self.ip,
            "timestamp": self.timestamp,
        }


@dataclass
class ParsedEmail:
    message: EmailMessage
    size: int
    text_body: str = ""
    html_body: str = ""
    attachments: list[EmailMessage] = field(default_factory=list)
    received_chain: list[ReceivedHop] = field(default_factory=list)


_RECEIVED_FROM = re.compile(r"from\s+(\S+)", re.IGNORECASE)
_RECEIVED_BY = re.compile(r"by\s+(\S+)", re.IGNORECASE)
_RECEIVED_IP = re.compile(r"\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,45})\]")


def _parse_received(value: str) -> ReceivedHop:
    hop = ReceivedHop(raw=value)
    # timestamp je za posledním středníkem
    if ";" in value:
        head, _, ts = value.rpartition(";")
        hop.timestamp = ts.strip() or None
    else:
        head = value
    m = _RECEIVED_FROM.search(head)
    if m:
        hop.from_host = m.group(1)
    m = _RECEIVED_BY.search(head)
    if m:
        hop.by_host = m.group(1)
    m = _RECEIVED_IP.search(head)
    if m:
        hop.ip = m.group(1)
    return hop


def _check_depth(msg: EmailMessage, depth: int = 0) -> None:
    if depth > MAX_MIME_DEPTH:
        raise ParseError(f"Překročena maximální hloubka MIME ({MAX_MIME_DEPTH}).")
    if msg.is_multipart():
        for part in msg.iter_parts():
            _check_depth(part, depth + 1)


def parse_bytes(data: bytes) -> ParsedEmail:
    if len(data) > MAX_FILE_SIZE:
        raise ParseError(
            f"Soubor je větší než limit {MAX_FILE_SIZE // (1024 * 1024)} MB."
        )
    msg = BytesParser(policy=policy.default).parsebytes(data)
    _check_depth(msg)

    parsed = ParsedEmail(message=msg, size=len(data))

    body = msg.get_body(preferencelist=("plain",))
    if body is not None:
        try:
            parsed.text_body = body.get_content()
        except Exception:
            parsed.text_body = ""
    body = msg.get_body(preferencelist=("html",))
    if body is not None:
        try:
            parsed.html_body = body.get_content()
        except Exception:
            parsed.html_body = ""

    for part in msg.walk():
        if part.get_content_disposition() == "attachment" or (
            part.get_filename() and not part.is_multipart()
        ):
            parsed.attachments.append(part)

    for value in msg.get_all("Received", []):
        parsed.received_chain.append(_parse_received(str(value)))

    return parsed


def parse_file(path: str | Path) -> ParsedEmail:
    p = Path(path)
    if p.stat().st_size > MAX_FILE_SIZE:
        raise ParseError(
            f"Soubor je větší než limit {MAX_FILE_SIZE // (1024 * 1024)} MB."
        )
    return parse_bytes(p.read_bytes())
