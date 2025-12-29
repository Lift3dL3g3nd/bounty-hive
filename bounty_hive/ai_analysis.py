from __future__ import annotations

from typing import List, Tuple

from .models import Context, PublicFinding, SealedFindingRef
from .findings import Finding


def ai_analyze_findings(
    ctx: Context,
    raw_findings: List[Finding],
) -> Tuple[List[PublicFinding], List[SealedFindingRef]]:
    """
    Stub implementation.

    This will be replaced with real LLM-powered analysis in Step 3.
    For now, it returns no AI findings and does nothing unsafe.
    """
    return [], []
