"""DNScurse — DNS recursor debug tool.

Library usage::

    from dnscurse import resolve, RecursionStep

    steps = resolve("example.com", "A")
    for step in steps:
        print(step.explain())
"""

from .models import (
    RecursionStep,
    format_rrset,
    get_cname_target,
    get_delegated_zone,
    get_referral_ns_ips,
    get_referral_ns_names,
    get_referral_ns_servers,
    is_referral,
)
from .resolver import (
    DEFAULT_TIMEOUT,
    MAX_CNAME_FOLLOWS,
    MAX_STEPS,
    ROOT_SERVERS,
    resolve,
    send_query,
)

__all__ = [
    # Core API
    "resolve",
    "send_query",
    "RecursionStep",
    # Constants
    "ROOT_SERVERS",
    "DEFAULT_TIMEOUT",
    "MAX_STEPS",
    "MAX_CNAME_FOLLOWS",
    # Response helpers
    "is_referral",
    "get_referral_ns_ips",
    "get_referral_ns_names",
    "get_referral_ns_servers",
    "get_cname_target",
    "get_delegated_zone",
    "format_rrset",
]
