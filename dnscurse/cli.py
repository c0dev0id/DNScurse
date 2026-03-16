"""CLI entry point for DNScurse — traceroute-style DNS resolution tracer."""

from __future__ import annotations

import argparse
import sys

import dns.rcode
import dns.rdatatype

from .models import (
    format_rrset,
    get_cname_target,
    get_delegated_zone,
    get_referral_ns_names,
    is_referral,
    RecursionStep,
)
from .resolver import resolve

# Common query types for CLI choices
_CLI_TYPES = ["A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "PTR"]

# ANSI escape codes for terminal color output
_DIM    = "\033[2m"
_YELLOW = "\033[33m"
_RESET  = "\033[0m"
_DASH   = "\u2014"

# 6 colors for hierarchy levels, cycling if depth exceeds 6
_LEVEL_COLORS = [
    "\033[31m",  # red
    "\033[32m",  # green
    "\033[33m",  # yellow
    "\033[35m",  # magenta
    "\033[36m",  # cyan
    "\033[37m",  # white
]


def _level_color(depth: int) -> str:
    return _LEVEL_COLORS[depth % len(_LEVEL_COLORS)]


def _colorize_domain(domain: str, zone: str | None, color: bool = True) -> str:
    """Return domain string with the resolved zone highlighted in yellow.

    The prefix (labels above the current zone) is dimmed, and the zone
    portion is yellow. This visually shows which part of the name each
    server in the delegation chain is responsible for.
    """
    domain_plain = domain.rstrip(".")
    if not color:
        return domain_plain

    zone_plain = zone.rstrip(".").lower() if zone else ""
    domain_lower = domain_plain.lower()

    if not zone_plain:
        return f"{_DIM}{domain_plain}{_RESET}"

    if zone_plain == domain_lower:
        return f"{_YELLOW}{domain_plain}{_RESET}"

    if domain_lower.endswith(zone_plain):
        # Split at the zone boundary, keeping the dot before the zone
        prefix = domain_plain[: -len(zone_plain)]
        zone_part = domain_plain[-len(zone_plain):]
        return f"{_DIM}{prefix}{_RESET}{_YELLOW}{zone_part}{_RESET}"

    # Fallback: full domain yellow
    return f"{_YELLOW}{domain_plain}{_RESET}"


def _format_result_line(step: RecursionStep) -> str:
    """One-line summary of what happened in this step."""
    if step.error:
        return f"error: {step.error}"

    resp = step.response
    if resp is None:
        return "(no response)"

    if resp.rcode() != dns.rcode.NOERROR:
        return dns.rcode.to_text(resp.rcode())

    if resp.answer:
        cname_target = get_cname_target(resp, step.query_name)
        if cname_target:
            return f"cname \u2192 {cname_target.rstrip('.')}"
        parts = []
        for rrset in resp.answer:
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            for rr in rrset:
                parts.append(f"{rtype} {rr}")
        return ", ".join(parts)

    if is_referral(resp):
        ns_names = get_referral_ns_names(resp)
        if ns_names:
            return "referral \u2192 " + ", ".join(ns_names)
        return "referral"

    return "NODATA"


def _format_tree(steps: list[RecursionStep], color: bool = True) -> str:
    """Format the resolution chain as a delegation tree.

    The query name is the root; each referral becomes a child node showing
    which zone was delegated and which server answered. The final leaf is
    the answer record (or error).

      dalek.home.codevoid.de A
        . (a.root-servers.net)
          └── de. (a.nic.de)
              └── codevoid.de. (ns1.codevoid.de)
                  └── home.codevoid.de. (ns.home.codevoid.de)
                      └── A 1.2.3.4
    """
    if not steps:
        return ""

    first = steps[0]
    lines = [f"{first.query_name} {first.query_type}"]

    # Build (zone_label, server_name) pairs for each node.
    # Node 0 is always the root zone ".".
    # Node N's zone label is what node N-1 referred to.
    nodes: list[tuple[str, str]] = [(".", first.server_name)]
    for prev, step in zip(steps, steps[1:]):
        zone = get_delegated_zone(prev) or "?"
        nodes.append((zone, step.server_name))

    # Color the query name: each label colored by its delegation depth,
    # matching the corresponding tree node color (rightmost label = depth 1).
    query_labels = first.query_name.rstrip(".").split(".")
    if color:
        colored_labels = [
            f"{_level_color(i + 1)}{label}{_RESET}"
            for i, label in enumerate(reversed(query_labels))
        ]
        colored_labels.reverse()
        lines[0] = ".".join(colored_labels) + f" {first.query_type}"

    def _color_zone(zone: str, depth: int) -> str:
        """Color only the leftmost label of a zone — the newly delegated part.

        e.g. depth=2, zone="example.com." → "[yellow]example[reset].com."
        The root "." is left uncolored since it isn't a label.
        """
        if not color:
            return zone
        if zone == ".":
            return f"{_DIM}.{_RESET}"
        # zone is like "com." or "example.com." — split off first label
        dot = zone.find(".")
        label = zone[:dot]
        rest = zone[dot:]  # includes the trailing dot
        c = _level_color(depth)
        return f"{c}{label}{_RESET}{rest}"

    con = f"{_DIM}\u2514\u2500\u2500 {_RESET}" if color else "\u2514\u2500\u2500 "

    for depth, (zone, server) in enumerate(nodes):
        if depth == 0:
            indent = "  "
            connector = ""
        else:
            indent = "    " * depth
            connector = con
        lines.append(f"{indent}{connector}{_color_zone(zone, depth)} ({server})")

    # Leaf: answer record(s) or error — color only the record type label
    final = steps[-1]
    leaf_depth = len(nodes)
    leaf_indent = "    " * leaf_depth + con
    lc = _level_color(leaf_depth) if color else ""
    lr = _RESET if color else ""
    # The leaf label is the leftmost label of the query name — the part
    # not covered by any delegation zone, colored at the leaf depth.
    leaf_label = query_labels[0]
    leaf_label_str = f"{lc}{leaf_label}{lr} " if color else ""

    if final.error:
        lines.append(f"{leaf_indent}{leaf_label_str}error: {final.error}")
    elif final.response and final.response.answer:
        for rrset in final.response.answer:
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            for rr in rrset:
                lines.append(f"{leaf_indent}{leaf_label_str}{rtype} {rr}")
    elif final.response:
        lines.append(f"{leaf_indent}{leaf_label_str}{dns.rcode.to_text(final.response.rcode())}")
    else:
        lines.append(f"{leaf_indent}{leaf_label_str}(no response)")

    return "\n".join(lines)


def _format_step_block(step: RecursionStep, color: bool = True) -> str:
    """Format one resolution step as an indented block.

    Header line shows the domain name with the resolved zone highlighted,
    followed by indented detail lines (server, rcode, result, time).
    """
    zone = get_delegated_zone(step)
    header = _colorize_domain(step.query_name, zone, color)

    resp = step.response
    if resp is not None and not step.error:
        rcode_text = dns.rcode.to_text(resp.rcode())
    else:
        rcode_text = _DASH

    if step.rtt_ms is not None:
        time_text = f"{step.rtt_ms:.1f}ms"
    else:
        time_text = _DASH

    server_text = f"{step.server_name} ({step.server_ip})"
    result_text = _format_result_line(step)

    lines = [
        header,
        f"  server  {server_text}",
        f"  rcode   {rcode_text}",
        f"  result  {result_text}",
        f"  time    {time_text}",
        "",
    ]
    return "\n".join(lines)


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

    steps = resolve(args.domain, rdtype, timeout=args.timeout)

    if not steps:
        print("No resolution steps.")
        return 1

    color = sys.stdout.isatty()

    if args.compact:
        print(_format_tree(steps, color=color))
        return 0

    for step in steps:
        print(_format_step_block(step, color=color))

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
