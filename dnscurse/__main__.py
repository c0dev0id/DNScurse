"""Allow running as `python -m dnscurse`."""

from ._cli import main

raise SystemExit(main())
