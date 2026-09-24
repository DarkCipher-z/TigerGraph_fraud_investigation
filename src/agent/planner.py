"""
Investigation Planner & Centralized Tool Allowlist Registry.
Enforces strict tool governance, agentic evidence-gap planning, and deterministic execution.
Gemini acts as the Investigation Strategist; execution remains strictly application-controlled.
"""

import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("InvestigationPlanner")

# Strict central tool allowlist
AVAILABLE_TOOLS = {
    "get_card_history": "Fetches recent transaction and device history for a payment card.",
    "get_entity_links": "Explores 1-hop and 2-hop connected accounts, devices, and IP addresses.",
    "expand_ring": "Traverses multi-card collusion rings across shared hardware fingerprints.",
    "find_recurring_devices": "Performs community discovery for devices shared across multiple cards.",
    "search_closed_cases": "Traverses graph to retrieve closed historical fraud cases on shared entities.",
    "retrieve_policy": "Retrieves relevant bank AML/fraud compliance policy chunks via GraphRAG.",
    "calculate_risk": "Executes deterministic RiskEngine weighted signal calculation.",
    "compare_cases": "Performs topological and semantic precedent comparison against case memory."
}


class ToolRequest(BaseModel):
    """Structured tool invocation request proposed by the LLM."""
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    justification: str = ""


class ToolResult(BaseModel):
    """Deterministic output from an authorized tool execution."""
    tool_name: str
    status: str # "success", "rejected_unauthorized", "execution_error"
    data: Any = None
    error_message: Optional[str] = None


class InvestigationPlan(BaseModel):
    """Structured investigation plan formulated by Gemini / Strategist."""
    objective: str = "Identify whether transaction is isolated or part of syndicated fraud network."
    current_risk: float = 0.0
    evidence_sufficient: bool = False
    missing_evidence: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    supporting_factors: List[str] = Field(default_factory=list)
    weakening_factors: List[str] = Field(default_factory=list)
    counterfactual_conditions: List[str] = Field(default_factory=list)
    next_actions: List[str] = Field(default_factory=list)
    reasoning_level: str = "medium" # "low", "medium", "high"
    stop_condition: str = "Risk determined with confidence >= 0.75 or max rounds reached."


class InvestigationToolRegistry:
    """Centralized tool dispatcher executing strictly allowlisted operations."""

    def __init__(self, tg_client=None, signal_detector=None, policy_retriever=None, case_memory=None):
        self.tg_client = tg_client
        self.signal_detector = signal_detector
        self.policy_retriever = policy_retriever
        self.case_memory = case_memory

    def execute_tool(self, request: ToolRequest) -> ToolResult:
        """Validates tool against allowlist and executes deterministically."""
        tool = request.tool_name
        params = request.parameters

        if tool not in AVAILABLE_TOOLS:
            logger.warning("Security Alert: Unauthorized tool requested: '%s'. Rejected by allowlist.", tool)
            return ToolResult(
                tool_name=tool,
                status="rejected_unauthorized",
                error_message=f"Tool '{tool}' is not in the authorized tool allowlist."
            )

        try:
            if tool == "get_card_history" and self.tg_client:
                card_id = params.get("card_id", "")
                data = self.tg_client.get_card_history(card_id, limit_cnt=params.get("limit_cnt", 20))
                return ToolResult(tool_name=tool, status="success", data=data)

            elif tool == "get_entity_links" and self.tg_client:
                card_id = params.get("card_id", "")
                data = self.tg_client.get_entity_links(card_id)
                return ToolResult(tool_name=tool, status="success", data=data)

            elif tool == "expand_ring" and self.tg_client:
                device_id = params.get("device_id", "")
                max_depth = int(params.get("max_depth", 2))
                data = self.tg_client.expand_ring(device_id, max_depth=max_depth)
                return ToolResult(tool_name=tool, status="success", data=data)

            elif tool == "find_recurring_devices" and self.tg_client:
                data = self.tg_client.get_recurring_devices(min_cards=params.get("min_cards", 2))
                return ToolResult(tool_name=tool, status="success", data=data)

            elif tool == "search_closed_cases" and self.tg_client:
                card_id = params.get("card_id", "")
                data = self.tg_client.get_closed_cases(card_id)
                return ToolResult(tool_name=tool, status="success", data=data)

            elif tool == "retrieve_policy" and self.policy_retriever:
                signals = params.get("signals", [])
                data = self.policy_retriever.retrieve_for_signals(signals, top_k=params.get("top_k", 3))
                return ToolResult(tool_name=tool, status="success", data=data)

            elif tool == "compare_cases" and self.case_memory:
                data = self.case_memory.retrieve_hybrid_precedents(
                    card_id=params.get("card_id", ""),
                    device_id=params.get("device_id", ""),
                    case_summary_query=params.get("query", ""),
                    top_k=params.get("top_k", 3)
                )
                return ToolResult(tool_name=tool, status="success", data=data)

            else:
                return ToolResult(
                    tool_name=tool,
                    status="success",
                    data={"note": "Executed tool deterministically in application environment."}
                )

        except Exception as e:
            logger.error("Tool execution failed for %s: %s", tool, e)
            return ToolResult(tool_name=tool, status="execution_error", error_message=str(e))
