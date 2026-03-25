# dnscurse/ui/output/short.py
import dns

from ... import models
from . import helpers
from .base import Outputter


class ShortOutputter(Outputter):
    def _output_steps(self) -> int:
        color = helpers._is_tty()
        prev_zone = None
        for step_idx, step in enumerate(self.steps):
            print(
                helpers._format_step_block(
                    step,
                    color=color,
                    parent_zone=prev_zone,
                    step_idx=step_idx,
                ),
                file=self.out,
            )
            prev_zone = models.get_delegated_zone(step)

        # final answer
        final = self.steps[-1]
        if final.response and final.response.answer:
            print("  Answer:", file=self.out)
            for rrset in final.response.answer:
                for line in models.format_rrset(rrset):
                    print(f"    {line}", file=self.out)
        elif final.error:
            print(f"  Resolution failed: {final.error}", file=self.out)
        elif final.response and final.response.rcode() != dns.rcode.NOERROR:
            print(
                f"  {dns.rcode.to_text(final.response.rcode())}",
                file=self.out
            )
        else:
            print("  No answer found.", file=self.out)

        # summary
        total_ms = sum(
            s.rtt_ms for s in self.steps
            if s.rtt_ms is not None
        )
        print(
            f"\n  {len(self.steps)} steps, {total_ms:.1f}ms total",
            file=self.out
        )

        return 0


