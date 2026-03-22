"""CLI entry point for DNScurse — traceroute-style DNS resolution tracer."""

from __future__ import annotations

import argparse
import sys

import dns.exception
import dns.name
import dns.rcode
import dns.rdatatype

from .models import (
    RecursionStep,
    format_rrset,
    get_cname_target,
    get_delegated_zone,
    get_referral_ns_names,
    get_referral_ns_servers,
    is_referral,
)
from .resolver import resolve

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
        "-c", "--compact",
        action="store_true",
        help="Compact tree view of the delegation chain",
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

    if not steps:
        print("No resolution steps.")
        return 1

    color = sys.stdout.isatty()

    if args.compact:
        print(_format_tree(steps, color=color))
        return 0

    prev_zone: str | None = None
    for step_idx, step in enumerate(steps):
        print(_format_step_block(step, color=color, parent_zone=prev_zone, step_idx=step_idx))
        prev_zone = get_delegated_zone(step)

    # Final answer summary
    final = steps[-1]
    if final.response and final.response.answer:
        print("  Answer:")
        for rrset in final.response.answer:
            for line in format_rrset(rrset):
                print(f"    {line}")
    elif final.error:
        print(f"  Resolution failed: {final.error}")
    elif final.response and final.response.rcode() != dns.rcode.NOERROR:
        print(f"  {dns.rcode.to_text(final.response.rcode())}")
    else:
        print("  No answer found.")

    total_ms = sum(s.rtt_ms for s in steps if s.rtt_ms is not None)
    print(f"\n  {len(steps)} steps, {total_ms:.1f}ms total")

    return 0


if __name__ == "__main__":
    sys.exit(main())
