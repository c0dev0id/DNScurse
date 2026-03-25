# Explicitly import subclasses you want to expose
from .base import Outputter
from .compact import CompactOutputter
from .dig import DigOutputter
from .pprint import PprintOutputter
from .short import ShortOutputter

# Optionally provide a registry for dynamic lookup
OUTPUTTERS = {
    "pprint": PprintOutputter,
    "short": ShortOutputter,
    "compact": CompactOutputter,
    "dig": DigOutputter,
}

# Make the API clean for `from dnscurse.ui.output import *`
__all__ = [
    "Outputter",
    "PprintOutputter",
    "ShortOutputter",
    "CompactOutputter",
    "DigOutputter",
    "OUTPUTTERS"
]
