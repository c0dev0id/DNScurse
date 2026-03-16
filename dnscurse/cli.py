"""CLI entry point for DNScurse — traceroute-style DNS resolution tracer."""

from __future__ import annotations

import argparse
import sys

import dns.rcode
import dns.rdatatype

from .models import (
    RecursionStep,
    get_referral_ns_names,
    is_referral,
)
from .resolver import resolve

# Common query types for CLI choices
_CLI_TYPES = ["A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "PTR"]


def _step_response_summary(step: RecursionStep) -> str:
    """One-line summary of what happened in this step."""
    if step.error:
        return f"ERROR: {step.error}"

    resp = step.response
    if resp is None:
        return "(no response)"

    rcode = dns.rcode.to_text(resp.rcode())

    if resp.rcode() != dns.rcode.NOERROR:
        return rcode

    if resp.answer:
        parts = []
        for rrset in resp.answer:
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            for rr in rrset:
                parts.append(f"{rtype} {rr}")
        return ", ".join(parts)

    if is_referral(resp):
        ns_names = get_referral_ns_names(resp)
        if ns_names:
            return "-> " + ", ".join(ns_names)
        return "-> (referral)"

    return "NODATA"


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

    args = parser.parse_args(argv)
    rdtype = dns.rdatatype.from_text(args.type)

    steps = resolve(args.domain, rdtype, timeout=args.timeout)

    if not steps:
        print("No resolution steps.")
        return 1

    # Compute column widths for alignment.
    col_step = 4  # " 1 " etc
    col_server = max(
        len(f"{s.server_name} ({s.server_ip})") for s in steps
    )
    col_query = max(
        len(f"{s.query_name} {s.query_type}") for s in steps
    )

    # Header
    hdr = (
        f"{'#':>{col_step}}  "
        f"{'SERVER':<{col_server}}  "
        f"{'QUERY':<{col_query}}  "
        f"{'TIME':>8}  "
        f"RESPONSE"
    )
    print(hdr)
    print("-" * len(hdr))

    # Rows
    for step in steps:
        num = f"{step.step_number:>{col_step}}"
        server = f"{step.server_name} ({step.server_ip})"
        query = f"{step.query_name} {step.query_type}"

        if step.rtt_ms is not None:
            rtt = f"{step.rtt_ms:>6.1f}ms"
        else:
            rtt = f"{'—':>8}"

        summary = _step_response_summary(step)

        print(
            f"{num}  "
            f"{server:<{col_server}}  "
            f"{query:<{col_query}}  "
            f"{rtt}  "
            f"{summary}"
        )

    # Final summary line
    final = steps[-1]
    print()
    if final.response and final.response.answer:
        for rrset in final.response.answer:
            for rr in rrset:
                rtype = dns.rdatatype.to_text(rrset.rdtype)
                print(f"  {rrset.name}  {rtype}  {rr}")
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
