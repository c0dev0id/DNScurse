# CLAUDE.md — DNScurse

## Project Overview

DNScurse is a Python CLI DNS recursor debug tool. It implements iterative DNS resolution from scratch, allowing users to walk through each recursion step to understand and debug how DNS resolution works.

## Critical Constraints

- **No DNS libraries.** Do not use `dnspython`, `socket.getaddrinfo()`, `socket.gethostbyname()`, or any library that performs DNS resolution or parsing.
- **All DNS logic must be hand-written.** Wire format encoding/decoding (per RFC 1035), packet construction, response parsing, and iterative resolution must all be implemented manually.
- **No copied implementations.** Code must be original, not lifted from existing DNS tools or libraries.
- **Minimal dependencies.** The core tool uses only Python stdlib (`socket` for raw UDP, `struct` for binary packing, `argparse` for CLI). No external packages for core functionality.

## Architecture

### DNS Wire Format (RFC 1035)
- Manual construction of DNS query packets (header, question section) as raw bytes
- Manual parsing of DNS response packets (header, question, answer, authority, additional sections)
- Support for label compression (pointer references in domain names)
- Record types: at minimum A, AAAA, NS, CNAME, SOA; extend as needed

### Iterative Resolution
- Start from root DNS servers (hardcoded root hints)
- Follow NS referrals down the delegation chain
- Handle CNAME chains
- Each step is exposed to the user for inspection

### Step-by-Step Walker
- The CLI allows pausing at each recursion step
- Display: query sent, server contacted, response received, next action
- Users can examine the raw packets and parsed data at each stage

## Project Structure

```
DNScurse/
├── CLAUDE.md
├── README.md
├── dnscurse/
│   ├── __init__.py
│   ├── cli.py          # CLI entry point and argument parsing
│   ├── wire.py         # DNS wire format encode/decode
│   ├── resolver.py     # Iterative resolution engine
│   └── models.py       # Data classes for DNS records, packets, etc.
├── tests/
│   ├── test_wire.py    # Unit tests for wire format
│   ├── test_resolver.py
│   └── test_models.py
└── pyproject.toml
```

## Development Setup

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Commands

```sh
# Run the tool
python -m dnscurse example.com

# Run tests
python -m pytest tests/

# Lint
python -m ruff check .

# Type check
python -m mypy dnscurse/
```

## Code Style

- PEP 8
- Type hints on all function signatures
- Docstrings on public functions (one-line or short)
- No classes where a function suffices
- Keep modules focused — wire format logic stays in `wire.py`, resolution logic in `resolver.py`

## Testing

- **Unit tests:** Encode a DNS query, verify raw bytes match expected. Parse a known response byte sequence, verify fields.
- **Integration tests:** Resolve a well-known domain (e.g., `example.com`) end-to-end against real root servers.
- Use `pytest`. No mocking of the DNS wire format — test against real byte sequences.

## Key References

- RFC 1035 — Domain Names: Implementation and Specification
- RFC 3596 — AAAA records
- Root server list: https://www.iana.org/domains/root/servers
