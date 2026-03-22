# Explicitly import subclasses you want to expose
from .pprint import PprintOutputter
from .short import ShortOutputter
from .compact import CompactOutputter
from .dig import DigOutputter
from .base import Outputter

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
