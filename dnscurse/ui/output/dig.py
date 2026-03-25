# dnscurse/ui/output/dig.py
from .base import Outputter


class DigOutputter(Outputter):
    def _output_steps(self) -> int:
        # implement dig-style output here
        print("this is not yet implemented")
        for step in self.steps:
            print(f"; {step.query_name} {step.query_type} {step.response}", file=self.out)
        return 0
