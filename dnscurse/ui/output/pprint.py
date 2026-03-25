# dnscurse/ui/output/pp.py
from .base import Outputter
import pprint


class PprintOutputter(Outputter):
    def _output_steps(self) -> int:
        pprint.pprint(self.steps)

        return 0
