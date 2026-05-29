from tools.forensic_common import redact_secrets


def test_redaction_of_tokens():
    text = "access_token: abcdefghijklmnop visible"
    redacted = redact_secrets(text)
    assert "abcdefghijklmnop" not in redacted
    assert "[REDACTED]" in redacted
