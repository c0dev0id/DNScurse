"""Allow running as `python -m dnscurse`."""

from .cli import main

raise SystemExit(main())
