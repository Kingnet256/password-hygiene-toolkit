#!/usr/bin/env python3
"""
password-hygiene-toolkit — defensive password auditing CLI.

Three commands:
  score       Estimate password strength (entropy + heuristics).
  breach      Check a password against Have I Been Pwned using the
              k-anonymity range API (only the first 5 SHA-1 chars ever
              leave your machine; the full hash and password never do).
  passphrase  Generate a strong, memorable diceware-style passphrase.

Nothing is logged, stored, or transmitted except the 5-char hash prefix
in `breach`. Intended for security-awareness training and self-auditing.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import re
import secrets
import sys
import urllib.request

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# Small built-in list of the most abused passwords, so `score` gives a
# useful verdict fully offline without shipping a giant wordlist.
COMMON = {
    "password", "123456", "123456789", "qwerty", "12345678", "111111",
    "1234567", "sunshine", "iloveyou", "admin", "welcome", "monkey",
    "letmein", "abc123", "football", "123123", "password1", "qwerty123",
    "dragon", "master", "login", "princess", "solo", "passw0rd",
}


def charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"[0-9]", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 33  # printable ASCII symbols
    return size or 1


def entropy_bits(pw: str) -> float:
    """Naive Shannon-style estimate: log2(charset ** length)."""
    return len(pw) * math.log2(charset_size(pw))


def verdict(bits: float) -> str:
    if bits < 28:
        return "VERY WEAK"
    if bits < 36:
        return "WEAK"
    if bits < 60:
        return "REASONABLE"
    if bits < 128:
        return "STRONG"
    return "VERY STRONG"


def score(pw: str) -> dict:
    lower = pw.lower()
    warnings = []
    if lower in COMMON:
        warnings.append("appears in the built-in common-password list")
    if re.fullmatch(r"\d+", pw):
        warnings.append("digits only")
    if re.fullmatch(r"[a-z]+", pw):
        warnings.append("lowercase letters only")
    if re.search(r"(.)\1{2,}", pw):
        warnings.append("contains a run of 3+ repeated characters")
    if re.search(r"(012|123|234|345|456|567|678|789|abc|qwe)", lower):
        warnings.append("contains a common sequence")
    bits = 0.0 if lower in COMMON else entropy_bits(pw)
    return {"length": len(pw), "bits": round(bits, 1),
            "verdict": verdict(bits), "warnings": warnings}


def breach_count(pw: str, *, timeout: float = 10.0) -> int:
    """Return how many times pw appears in HIBP, via k-anonymity range API."""
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        HIBP_RANGE_URL.format(prefix=prefix),
        headers={"User-Agent": "password-hygiene-toolkit"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    for line in body.splitlines():
        tail, _, count = line.partition(":")
        if tail.strip() == suffix:
            return int(count)
    return 0


WORDS = [
    "anchor", "bramble", "cobalt", "dune", "ember", "fjord", "granite",
    "harbor", "ivory", "juniper", "kelp", "lantern", "meadow", "nimbus",
    "orchard", "pewter", "quartz", "ripple", "saffron", "thistle",
    "umber", "velvet", "willow", "xenon", "yarrow", "zephyr",
]


def passphrase(words: int = 5, sep: str = "-") -> str:
    return sep.join(secrets.choice(WORDS) for _ in range(words))


def _read_password(arg: str | None) -> str:
    if arg is not None:
        return arg
    import getpass
    return getpass.getpass("Password (hidden): ")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("score", help="estimate strength (offline)")
    sp.add_argument("password", nargs="?", help="omit to be prompted (hidden)")

    bp = sub.add_parser("breach", help="check HIBP via k-anonymity")
    bp.add_argument("password", nargs="?", help="omit to be prompted (hidden)")

    gp = sub.add_parser("passphrase", help="generate a passphrase")
    gp.add_argument("-n", "--words", type=int, default=5)
    gp.add_argument("-s", "--sep", default="-")

    args = p.parse_args(argv)

    if args.cmd == "score":
        pw = _read_password(args.password)
        r = score(pw)
        print(f"length   : {r['length']}")
        print(f"entropy  : {r['bits']} bits ({r['verdict']})")
        if r["warnings"]:
            print("warnings :")
            for w in r["warnings"]:
                print(f"  - {w}")
        else:
            print("warnings : none")
        return 0

    if args.cmd == "breach":
        pw = _read_password(args.password)
        try:
            n = breach_count(pw)
        except Exception as e:  # network/API errors shouldn't crash the tool
            print(f"error: could not reach HIBP ({e})", file=sys.stderr)
            return 2
        if n:
            print(f"BREACHED: seen {n:,} times in known breaches. Do not use it.")
            return 1
        print("Not found in HIBP's breach corpus (still no guarantee it's strong).")
        return 0

    if args.cmd == "passphrase":
        print(passphrase(args.words, args.sep))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
