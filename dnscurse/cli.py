"""CLI entry point for DNScurse."""

from __future__ import annotations

import argparse
import sys

from .models import QType
from .resolver import resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dnscurse",
        description="Walk DNS recursion steps for a domain name.",
    )
    parser.add_argument("domain", help="Domain name to resolve")
    parser.add_argument(
        "-t", "--type",
        default="A",
        choices=[t.name for t in QType],
        help="Query type (default: A)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-query UDP timeout in seconds (default: 5)",
    )

    args = parser.parse_args(argv)
    qtype = QType[args.type]

    steps = resolve(args.domain, qtype, timeout=args.timeout)

    for step in steps:
        print(step.explain())
        print()

    # Summary
    final = steps[-1] if steps else None
    if final and final.response and final.response.answers:
        print("--- Final Answer ---")
        for r in final.response.answers:
            print(f"  {r}")
    elif final and final.error:
        print(f"--- Resolution failed: {final.error} ---")
    else:
        print("--- No answer found ---")

    return 0


if __name__ == "__main__":
    sys.exit(main())
