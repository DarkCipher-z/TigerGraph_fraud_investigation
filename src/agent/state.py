"""
Investigation State Machine Models.
Tracks state, evidence rounds, fired signals, graph artifacts, and audit events.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class CaseEvent(BaseModel):
    step_number: int
    step_name: str
    event_payload: Dict[str, Any]
    llm_provider: Optional[str] = None
    latency_ms: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProposedAction(BaseModel):
    action_type: str
    target_entity: str
    is_critical: bool
    requires_human_approval: bool
    justification: str
    stage: str = "pre_evidence" # "pre_evidence" or "post_evidence"
    status: str = "proposed"     # "proposed", "approved", "rejected", "executed"
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None


class InvestigationState(BaseModel):
    case_id: str
    trigger_data: Dict[str, Any]
    current_round: int = 1
    status: str = "open"
    
    # Graph & Context
    graph_context: Dict[str, Any] = Field(default_factory=dict)
    fired_signals: List[Dict[str, Any]] = Field(default_factory=list)
    retrieved_policies: List[Dict[str, Any]] = Field(default_factory=list)
    similar_cases: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Quantitative Assessment & Real Evolution History
    risk_score: float = 0.0
    confidence: float = 0.0
    uncertainty: float = 0.0
    risk_tier: str = "LOW"
    primary_typology: str = "Unclassified"
    requires_evidence: bool = False
    evidence_gaps: List[str] = Field(default_factory=list)
    signal_contributions: List[Dict[str, Any]] = Field(default_factory=list)
    memory_adjustment: float = 0.0
    raw_risk: float = 0.0
    initial_assessment: Optional[Dict[str, Any]] = None
    assessment_history: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Decisions & Actions
    actions_pre_evidence: List[ProposedAction] = Field(default_factory=list)
    actions_post_evidence: List[ProposedAction] = Field(default_factory=list)
    final_disposition: str = "inconclusive"
    reasoning_summary: str = ""
    
    # Evidence Validation & Agentic Planner Artefacts
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    integrity_report: Dict[str, Any] = Field(default_factory=dict)
    investigation_plan: Optional[Dict[str, Any]] = None
    supporting_evidence: List[str] = Field(default_factory=list)
    weakening_evidence: List[str] = Field(default_factory=list)
    counterfactual_notes: str = ""
    contradiction_notes: str = ""
    
    # SAR Filing
    requires_sar: bool = False
    sar_narrative: Optional[str] = None
    sar_reference_id: Optional[str] = None
    
    # Audit trail of 8 steps
    events: List[CaseEvent] = Field(default_factory=list)
    
    # Telemetry, Provider & Execution Tracking
    primary_llm_provider: Optional[str] = None
    llm_model_name: Optional[str] = None
    thinking_level_used: str = "medium"
    total_execution_ms: int = 0
    executed_queries: List[Dict[str, Any]] = Field(default_factory=list)
    step_latencies_ms: Dict[str, int] = Field(default_factory=dict)

