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
- **CLI** (`_cli.py`): reference implementation / entry point (internal, not part of the public API)

### Key design decisions
- Queries are sent with `RD=0` (Recursion Desired off) — we do the iteration ourselves
- `dns.message.Message` is used directly as the response type (no wrapper layer)
- `RecursionStep` is our only custom data class — it wraps a response with metadata about which server was queried and why

## Project Structure

```
DNScurse/
├── CLAUDE.md
├── README.md
├── Makefile
├── pyproject.toml
├── .gitignore
├── .github/workflows/test.yml
├── dnscurse/
│   ├── __init__.py        # Public library API (resolve, RecursionStep, helpers)
│   ├── __main__.py        # python -m dnscurse
│   ├── _cli.py            # Internal — CLI reference implementation
│   ├── models.py          # RecursionStep + helper functions for dns.message.Message
│   └── resolver.py        # Iterative resolution engine
├── man/
│   ├── dnscurse.1         # User command man page
│   └── dnscurse.3         # Library API man page
├── docs/
│   └── ARCHITECTURE.md    # In-depth architecture documentation
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_models.py     # Library: referral/CNAME detection, RecursionStep explanations
    ├── test_resolver.py   # Library: simulated resolution chains, root server config
    └── test_cli.py        # CLI: argument parsing, output formatting, exit codes
```

## Commands

```sh
# Install
pip install -e ".[dev]"

# Run the tool
python -m dnscurse example.com
python -m dnscurse -t AAAA example.com

# Run tests (no network)
python -m pytest tests/ -m "not network"

# Run integration tests (requires network)
python -m pytest tests/ -m network

# Run only library or CLI tests via markers
python -m pytest tests/ -m "not network and not cli"
python -m pytest tests/ -m "cli"
```

## Code Style

- PEP 8
- Type hints on all function signatures
- Use `dns.rdatatype`, `dns.rcode`, `dns.message.Message` directly — no wrapper enums
- Keep modules focused: resolution logic in `resolver.py`, helpers and `RecursionStep` in `models.py`, CLI rendering in `_cli.py`
- `_cli.py` is internal — the public API is `__init__.py` (which exports only from `models.py` and `resolver.py`)

## Testing

- **Unit tests**: Mock `send_query` to simulate referral chains, CNAMEs, NXDOMAIN, network errors
- **Helper `_msg()`**: Builds `dns.message.Message` objects from simple tuples for readable tests
- **Integration tests** (`@pytest.mark.network`): Resolve real domains against root servers
- Test output explains each recursion step — serves as educational documentation
