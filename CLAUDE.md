# CLAUDE.md — DNScurse

## Project Overview

DNScurse is a Python CLI DNS recursor debug tool. It performs iterative DNS resolution from root servers, allowing users to walk through each recursion step to understand and debug how DNS resolution works.

## Dependencies

- **dnspython** (`>=2.6`) — handles DNS wire format encoding/decoding, packet construction/parsing, and UDP transport.
- **Python stdlib** — `argparse` for CLI.
- **No other external packages** for core functionality.

## Architecture

### What dnspython handles
- Wire format (RFC 1035): packet encoding, decoding, name compression
- Record type parsing: A, AAAA, NS, CNAME, SOA, MX, TXT, etc.
- UDP transport: `dns.query.udp()`
- Query construction: `dns.message.make_query()`

### What we implement
- **Iterative resolution logic** (`resolver.py`): walks the delegation chain from root servers, follows referrals and CNAMEs
- **Referral/CNAME detection** (`models.py`): helper functions that inspect `dns.message.Message` objects
- **Step-by-step explanation** (`models.py`): `RecursionStep` with `explain()` for human-readable output
- **CLI** (`cli.py`): entry point

### Key design decisions
- Queries are sent with `RD=0` (Recursion Desired off) — we do the iteration ourselves
- `dns.message.Message` is used directly as the response type (no wrapper layer)
- `RecursionStep` is our only custom data class — it wraps a response with metadata about which server was queried and why

## Project Structure

```
DNScurse/
├── CLAUDE.md
├── pyproject.toml
├── .gitignore
├── .github/workflows/test.yml
├── dnscurse/
│   ├── __init__.py
│   ├── __main__.py       # python -m dnscurse
│   ├── cli.py             # CLI entry point and argument parsing
│   ├── models.py          # RecursionStep + helper functions for dns.message.Message
│   └── resolver.py        # Iterative resolution engine
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_models.py     # Referral/CNAME detection, RecursionStep explanations
    └── test_resolver.py   # Simulated resolution chains, root server config
```

## Commands

```sh
# Install
pip install -e ".[dev]"

# Run the tool
python -m dnscurse example.com
python -m dnscurse -t AAAA example.com

# Run tests
python -m pytest tests/ -m "not network"

# Run integration tests (requires network)
python -m pytest tests/ -m network
```

## Code Style

- PEP 8
- Type hints on all function signatures
- Use `dns.rdatatype`, `dns.rcode`, `dns.message.Message` directly — no wrapper enums
- Keep modules focused: resolution logic in `resolver.py`, helpers and `RecursionStep` in `models.py`

## Testing

- **Unit tests**: Mock `send_query` to simulate referral chains, CNAMEs, NXDOMAIN, network errors
- **Helper `_msg()`**: Builds `dns.message.Message` objects from simple tuples for readable tests
- **Integration tests** (`@pytest.mark.network`): Resolve real domains against root servers
- Test output explains each recursion step — serves as educational documentation
