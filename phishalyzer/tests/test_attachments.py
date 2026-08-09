import hashlib

from phishalyzer.attachments import analyze_attachments, sanitize_filename


def ids(findings):
    return {f.id for f in findings}


def test_sanitize_filename():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("a\x00b\r\n.txt") == "ab.txt"
    assert sanitize_filename("faktura (1).pdf") == "faktura (1).pdf"
    assert sanitize_filename("") == "unnamed"


def test_double_extension_and_mismatch(load):
    findings, infos = analyze_attachments(load("double_extension.eml").attachments)
    found = ids(findings)
    assert "dangerous_extension" in found
    assert "double_extension" in found
    assert infos[0].filename == "faktura.pdf.exe"
    # sha256 sedí na skutečný obsah
    raw = load("double_extension.eml").attachments[0].get_payload(decode=True)
    assert infos[0].sha256 == hashlib.sha256(raw).hexdigest()


def test_macro_format(load):
    findings, _ = analyze_attachments(load("macro_attachment.eml").attachments)
    assert "macro_format" in ids(findings)


def test_password_zip(load):
    findings, _ = analyze_attachments(load("password_zip.eml").attachments)
    found = ids(findings)
    assert "password_protected_archive" in found
    assert "archive_contains_executable" in found


def test_no_attachments():
    findings, infos = analyze_attachments([])
    assert findings == [] and infos == []
