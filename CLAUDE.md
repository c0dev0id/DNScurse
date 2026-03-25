# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

DNScurse is a DNS iterative resolution library and CLI tool. It resolves domains from root servers, recording each recursion step. The library (`from dnscurse import resolve`) is the public API; the CLI (`dnscurse example.com`) is an internal reference implementation.

## Commands

The Makefile manages a `.venv` automatically — use `make` targets, not raw pip/pytest.

```sh
make build                # dev install (editable + dev deps)
make test                 # unit tests (no network)
make test-net             # integration tests (hits real DNS)
make lint                 # ruff check
make run ARGS="example.com"           # run the tool
make run ARGS="-t AAAA example.com"   # run with flags
```

Single test: `pytest tests/test_models.py::TestReferralDetection::test_referral_detected -v`

Linter is **ruff** — line-length=100, rules: E/F/W/I (see `pyproject.toml`).

## Architecture

### Dependency layering

```
_cli.py → ui/output/ → resolver.py + models.py → dnspython
```

### Modules — what goes where

- **`resolver.py`** — iterative resolution engine. Walks the delegation chain from root servers, follows referrals and CNAMEs. Contains `send_query()` (sole network boundary) and `resolve()`.
- **`models.py`** — `RecursionStep` dataclass + helper functions (`is_referral`, `get_cname_target`, `get_referral_ns_names`, `get_referral_ns_servers`) that inspect `dns.message.Message` objects.
- **`ui/output/`** — pluggable CLI formatters. `Outputter` base class in `base.py`; four implementations: `short`, `compact`, `pprint`, `dig`. `OUTPUTTERS` dict in `__init__.py` maps names to classes. CLI selects via `-o`/`--output`.
- **`_cli.py`** — CLI entry point (internal, not part of the public API). Parses args, calls `resolve()`, picks an outputter from `OUTPUTTERS`, prints results.
- **`__init__.py`** — public library API. Exports only from `models.py` and `resolver.py`.

### Key design decisions

- Queries use `RD=0` — we do the iteration ourselves
- `dns.message.Message` is used directly as the response type (no wrapper layer)
- `RecursionStep` is our only custom data class — wraps a response with metadata about which server was queried and why
- `send_query()` is the sole network boundary — monkeypatched in tests

## Code Style

- Type hints on all function signatures
- Use `dns.rdatatype`, `dns.rcode`, `dns.message.Message` directly — no wrapper enums

## Testing

Unit tests mock `send_query` to simulate full resolution chains without network access.

**Pattern** — define a `fake_send()` keyed on `(name, rdtype, server_ip)`, then:
```python
with patch("dnscurse.resolver.send_query", side_effect=fake_send):
    steps = resolve("example.com", dns.rdatatype.A)
```

**`_msg()` helper** (in `conftest.py`) — builds `dns.message.Message` from simple tuples:
```python
_msg(authority=[("com.", dns.rdatatype.NS, 172800, "ns1.com.")],
     additional=[("ns1.com.", dns.rdatatype.A, 172800, "10.0.0.1")])
```

**Markers**: `@pytest.mark.network` for integration tests, `@pytest.mark.cli` for CLI tests.
