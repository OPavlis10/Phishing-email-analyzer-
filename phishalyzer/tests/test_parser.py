import pytest

from phishalyzer.parser import MAX_FILE_SIZE, ParseError, parse_bytes


def test_parses_bodies_and_received(load):
    parsed = load("link_text_mismatch.eml")
    assert "csas.cz" in parsed.text_body
    assert "<a href" in parsed.html_body
    assert parsed.received_chain
    hop = parsed.received_chain[0]
    assert hop.ip == "203.0.113.5"
    assert hop.from_host == "mail.example.net"
    assert hop.timestamp is not None


def test_decodes_encoded_headers(load):
    parsed = load("display_name_encoded.eml")
    assert "Komerční banka" in str(parsed.message["From"])


def test_size_limit():
    with pytest.raises(ParseError):
        parse_bytes(b"x" * (MAX_FILE_SIZE + 1))


def test_attachment_collection(load):
    parsed = load("double_extension.eml")
    assert len(parsed.attachments) == 1
