"""Closed identifiers for Stage 6 acceptance evidence contracts.

This module intentionally has no checker imports: both source gates use the
same exact identifier rule without creating an import cycle.
"""

EVIDENCE_CONTRACT_PREFIX = "forge.p2p.evidence."
EVIDENCE_CONTRACT_SUFFIX = ".v1"


def evidence_contract_for(scenario_id: str) -> str:
    return f"{EVIDENCE_CONTRACT_PREFIX}{scenario_id}{EVIDENCE_CONTRACT_SUFFIX}"
