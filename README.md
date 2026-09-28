# password-hygiene-toolkit

A small, dependency-free **defensive** password auditing CLI for
security-awareness training and personal self-checks.

It does three things:

| Command | What it does | Network? |
|---|---|---|
| `score` | Estimates strength (entropy + common-password/pattern heuristics) | No — fully offline |
| `breach` | Checks a password against [Have I Been Pwned](https://haveibeenpwned.com) | Only sends the first **5 characters** of the SHA-1 hash (k-anonymity) |
| `passphrase` | Generates a strong, memorable diceware-style passphrase | No |

The full password and full hash **never leave your machine**. `breach`
uses HIBP's [range API](https://haveibeenpwned.com/API/v3#PwnedPasswords),
so only a 5-character hash prefix is sent and the count is matched locally.

## Usage

```bash
# Offline strength check (omit the password to be prompted with hidden input)
python3 src/pwtool.py score
python3 src/pwtool.py score "correct horse battery staple"

# Breach check via k-anonymity (privacy-preserving)
python3 src/pwtool.py breach

# Generate a passphrase
python3 src/pwtool.py passphrase -n 6 -s .
```

## Why this exists

Most password advice is abstract. This gives people a concrete, private
way to see *why* a password is weak (low entropy, common patterns, or
already in a breach corpus) without ever exposing the password itself —
which is exactly the point you want to make in an awareness session.

## Requirements

Python 3.8+. No third-party dependencies. `breach` needs internet access.

## Tests

```bash
python3 -m pytest tests/     # or just run the module directly to eyeball it
```

## License

MIT — see [LICENSE](LICENSE).

> Defensive/educational tool. Only check passwords you own or are
> authorized to audit.
