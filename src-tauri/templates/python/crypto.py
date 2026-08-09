"""Algorithm steps recovered from the capture.

Only steps that were executed against values this capture recorded, and
reproduced them exactly, appear here as code. Steps that were identified
but never reproduced a captured value are listed in GAPS.md and are not
guessed at: a signature that is almost right fails the same as no
signature, and it fails less visibly.
"""

from __future__ import annotations

__SHOWNET_STEPS__

VERIFIED_STEPS: dict[str, object] = __SHOWNET_STEP_INDEX__
