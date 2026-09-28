import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pwtool  # noqa: E402


def test_common_password_scores_zero():
    r = pwtool.score("password")
    assert r["bits"] == 0.0
    assert r["verdict"] == "VERY WEAK"
    assert any("common" in w for w in r["warnings"])


def test_strong_passphrase_scores_high():
    r = pwtool.score("anchor-quartz-willow-nimbus-saffron")
    assert r["bits"] > 60
    assert r["verdict"] in ("STRONG", "VERY STRONG")


def test_digits_only_flagged():
    r = pwtool.score("12345678")
    assert any("digits only" in w for w in r["warnings"])


def test_charset_size():
    assert pwtool.charset_size("abc") == 26
    assert pwtool.charset_size("Abc1!") == 26 + 26 + 10 + 33


def test_passphrase_shape():
    pp = pwtool.passphrase(4, "-")
    assert len(pp.split("-")) == 4
