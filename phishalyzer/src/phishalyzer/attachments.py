"""Analýza příloh. Nikdy je neotvíráme ani nespouštíme — jen bajty a metadata.

Typ podle magic bytes (puremagic — čistý Python, žádný libmagic).
SHA-256 se dá bezpečně poslat do VirusTotalu, samotný soubor ne.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from email.message import EmailMessage

import puremagic

from .findings import Finding, Severity

MAX_ZIP_ENTRIES = 200
MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB — ochrana proti zip bombě

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".hta", ".msi", ".jar", ".lnk", ".iso", ".img", ".ps1",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}
LEGACY_OFFICE = {".doc", ".xls", ".ppt"}  # mohou obsahovat makra bez rozlišení v příponě
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

_SAFE_NAME = re.compile(r"[^\w.\- ()\[\]]")


def sanitize_filename(name: str) -> str:
    """Odstraní ../, řídicí znaky a vše mimo bezpečnou sadu — název přílohy
    je nepřátelský vstup a někde ho vypisujeme."""
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable())
    return _SAFE_NAME.sub("_", name) or "unnamed"


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str
    detected_type: str | None = None

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "detected_type": self.detected_type,
        }


def _extensions(filename: str) -> list[str]:
    parts = filename.lower().split(".")
    return ["." + p for p in parts[1:]]


def _detect_type(data: bytes) -> tuple[str | None, set[str]]:
    """(popis, množina přípon, které magic bytes připouštějí)"""
    try:
        matches = puremagic.magic_string(data)
    except Exception:
        return None, set()
    if not matches:
        return None, set()
    exts = {m.extension.lower() for m in matches if m.extension}
    return matches[0].name or matches[0].extension, exts


def analyze_attachments(parts: list[EmailMessage]) -> tuple[list[Finding], list[AttachmentInfo]]:
    findings: list[Finding] = []
    infos: list[AttachmentInfo] = []

    for part in parts:
        raw_name = part.get_filename() or "unnamed"
        name = sanitize_filename(raw_name)
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""

        detected, magic_exts = _detect_type(data)
        info = AttachmentInfo(
            filename=name,
            content_type=part.get_content_type(),
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            detected_type=detected,
        )
        infos.append(info)

        exts = _extensions(name)
        last_ext = exts[-1] if exts else ""

        if name != raw_name.replace("\\", "/").split("/")[-1]:
            findings.append(Finding(
                id="attachment_name_suspicious_chars",
                severity=Severity.MEDIUM,
                title="Název přílohy obsahuje cestu nebo řídicí znaky",
                evidence={"sanitized": name, "raw_repr": repr(raw_name)},
                explanation="../ nebo řídicí znaky v názvu jsou běžný trik.",
            ))

        if last_ext in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                id="dangerous_extension",
                severity=Severity.CRITICAL,
                title=f"Spustitelná nebo skriptová příloha ({last_ext})",
                evidence={"filename": name, "sha256": info.sha256},
                explanation=(
                    "Legitimní korespondence spustitelné soubory mailem neposílá."
                ),
            ))

        if len(exts) >= 2 and last_ext in DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS:
            findings.append(Finding(
                id="double_extension",
                severity=Severity.HIGH,
                title="Dvojitá přípona",
                evidence={"filename": name, "extensions": exts},
                explanation=(
                    "faktura.pdf.exe — klient s vypnutým zobrazením přípon "
                    "ukáže jen faktura.pdf."
                ),
            ))

        if last_ext in MACRO_EXTENSIONS:
            findings.append(Finding(
                id="macro_format",
                severity=Severity.HIGH,
                title=f"Formát s podporou maker ({last_ext})",
                evidence={"filename": name, "sha256": info.sha256},
                explanation="Makra v dokumentech jsou hlavní cesta k spuštění kódu.",
            ))
        elif last_ext in LEGACY_OFFICE:
            findings.append(Finding(
                id="legacy_office_format",
                severity=Severity.MEDIUM,
                title=f"Starý formát Office ({last_ext})",
                evidence={"filename": name},
                explanation=(
                    "Binární formáty .doc/.xls/.ppt mohou obsahovat makra, "
                    "aniž by to přípona prozradila."
                ),
            ))

        # nesoulad přípony a skutečného obsahu
        if last_ext and magic_exts and last_ext not in magic_exts:
            # OOXML dokumenty jsou zip — to není nesoulad
            ooxml = last_ext in {".docx", ".xlsx", ".pptx"} | MACRO_EXTENSIONS
            if not (ooxml and ".zip" in magic_exts):
                findings.append(Finding(
                    id="extension_content_mismatch",
                    severity=Severity.HIGH,
                    title="Přípona neodpovídá skutečnému obsahu",
                    evidence={"filename": name, "extension": last_ext,
                              "detected": detected,
                              "magic_extensions": sorted(magic_exts)},
                    explanation=(
                        "Skutečný typ souboru určují magic bytes, ne přípona. "
                        "Nesoulad znamená, že se soubor za něco vydává."
                    ),
                ))

        if last_ext in ARCHIVE_EXTENSIONS or ".zip" in magic_exts:
            findings.extend(_analyze_zip(name, data, info.sha256))

    return findings, infos


def _analyze_zip(name: str, data: bytes, sha256: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return findings

    entries = zf.infolist()
    if len(entries) > MAX_ZIP_ENTRIES:
        findings.append(Finding(
            id="zip_too_many_entries",
            severity=Severity.HIGH,
            title="Archiv obsahuje podezřele mnoho položek",
            evidence={"filename": name, "entries": len(entries),
                      "limit": MAX_ZIP_ENTRIES},
            explanation="Ochrana proti zip bombě — dál archiv nerozebíráme.",
        ))
        return findings

    total_uncompressed = sum(e.file_size for e in entries)
    if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
        findings.append(Finding(
            id="zip_bomb_suspect",
            severity=Severity.HIGH,
            title="Archiv se rozbaluje na podezřele velký objem",
            evidence={"filename": name,
                      "uncompressed_bytes": total_uncompressed,
                      "compressed_bytes": len(data)},
            explanation="Extrémní kompresní poměr je znak zip bomby.",
        ))

    if any(e.flag_bits & 0x1 for e in entries):
        findings.append(Finding(
            id="password_protected_archive",
            severity=Severity.HIGH,
            title="Archiv chráněný heslem",
            evidence={"filename": name, "sha256": sha256},
            explanation=(
                "Klasický trik na obejití skenerů: heslo je v těle mailu, "
                "aby ho uživatel našel a skener ne."
            ),
        ))

    for e in entries:
        inner_ext = "." + e.filename.lower().rsplit(".", 1)[-1] if "." in e.filename else ""
        if inner_ext in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                id="archive_contains_executable",
                severity=Severity.CRITICAL,
                title="Archiv obsahuje spustitelný soubor",
                evidence={"archive": name,
                          "entry": sanitize_filename(e.filename)},
                explanation="Zabalení do archivu je běžná cesta kolem filtrů.",
            ))
            break

    return findings
