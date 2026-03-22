# dnscurse/ui/output/base.py
import sys
from .exceptions import NoResolutionSteps

class Outputter:
    def __init__(self, steps, compact=False, out=sys.stdout):
        self.steps = steps
        self.compact = compact
        self.out = out

    def output(self) -> int:
        """High-level entry point."""
        if not self.steps:
            raise NoResolutionSteps("No resolution steps")
        return self._output_steps()

    def _output_steps(self) -> int:
        """Subclasses implement actual printing."""
        raise NotImplementedError
