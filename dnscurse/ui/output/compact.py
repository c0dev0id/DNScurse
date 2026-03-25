# dnscurse/ui/output/compact.py
from . import helpers
from .short import ShortOutputter


class CompactOutputter(ShortOutputter):
    def _output_steps(self) -> int:
        color = helpers._is_tty()
        print(helpers._format_tree(self.steps, color=color), file=self.out)

        return 0
