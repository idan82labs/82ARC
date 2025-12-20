"""
Kill Chain Campaign Framework

Automated attack campaign orchestration following
Lockheed Martin Cyber Kill Chain and MITRE ATT&CK.
"""

from .kill_chain import (
    KillChainOrchestrator,
    CampaignState,
    TechniqueLibrary,
    CampaignTemplates,
    KillChainPhase,
    AttackStatus,
    OPSECLevel,
    Technique,
    Target,
    CampaignObjective,
    PhaseResult,
    create_campaign,
    run_quick_campaign,
)

__all__ = [
    "KillChainOrchestrator",
    "CampaignState",
    "TechniqueLibrary",
    "CampaignTemplates",
    "KillChainPhase",
    "AttackStatus",
    "OPSECLevel",
    "Technique",
    "Target",
    "CampaignObjective",
    "PhaseResult",
    "create_campaign",
    "run_quick_campaign",
]
