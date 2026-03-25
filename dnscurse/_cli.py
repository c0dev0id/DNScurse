"""CLI entry point for DNScurse — traceroute-style DNS resolution tracer."""

from __future__ import annotations

import argparse
import sys

import dns.exception
import dns.name
import dns.rcode
import dns.rdatatype

from .resolver import resolve
from .ui.output import OUTPUTTERS
from .ui.output.exceptions import NoResolutionSteps

# Common query types for CLI choices
_CLI_TYPES = ["A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "PTR"]

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnscurse",
        description="Trace DNS recursion steps like traceroute.",
    )
    parser.add_argument("domain", help="Domain name to resolve")
    parser.add_argument(
        "-t", "--type",
        default="A",
        choices=_CLI_TYPES,
        help="Query type (default: A)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-query UDP timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-o", "--output",
        default="short",
        choices=OUTPUTTERS.keys(),
        help="Output format (default: short)",
    )
    parser.add_argument(
        "-c", "--compact",
        action="store_true",
        help="Compact tree view of the delegation chain (sets output=compact)",
    )

    args = parser.parse_args(argv)
    rdtype = dns.rdatatype.from_text(args.type)

    try:
        dns.name.from_text(args.domain)
    except (dns.exception.DNSException, ValueError) as exc:
        print(
            f"error: invalid domain name '{args.domain}': {exc}",
            file=sys.stderr
        )
        return 1

    steps = resolve(args.domain, rdtype, timeout=args.timeout)

    if args.compact:
        args.output="compact"

    OutputterClass = OUTPUTTERS.get(args.output)
    if not OutputterClass:
        print(f"no OutputterClass found for output {args.output}, falling back to short")
        OutputterClass = OUTPUTTERS.get("short")
    try:
        return OutputterClass(steps).output()
    except NoResolutionSteps as e:
        print(e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
