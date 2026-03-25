# dnscurse/ui/output/base.py
import sys

from .exceptions import NoResolutionSteps


class Outputter:
    def __init__(self, steps, compact=False, out=None):
        self.steps = steps
        self.compact = compact
        self.out = out if out is not None else sys.stdout

    def output(self) -> int:
        """High-level entry point."""
        if not self.steps:
            raise NoResolutionSteps("No resolution steps")
        return self._output_steps()

    def _output_steps(self) -> int:
        """Subclasses implement actual printing."""
        raise NotImplementedError
