# dnscurse/ui/output/pp.py
import pprint

from .base import Outputter


class PprintOutputter(Outputter):
    def _output_steps(self) -> int:
        pprint.pprint(self.steps)

        return 0
