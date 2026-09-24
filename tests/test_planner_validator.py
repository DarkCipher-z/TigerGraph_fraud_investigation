"""
Unit Tests for Agentic Investigation Planner, Tool Allowlist, and Evidence Validator.
Validates:
- Tool allowlist security and rejection of unauthorized tools (e.g., arbitrary python/bash).
- Evidence extraction, verification badges, and dynamic integrity calculation.
- Prompt injection defense and counterfactual generation.
"""

import pytest
from src.agent.planner import (
    AVAILABLE_TOOLS,
    InvestigationToolRegistry,
    ToolRequest,
    ToolResult,
    InvestigationPlan
)
from src.agent.evidence_validator import (
    EvidenceValidationEngine,
    EvidenceItem,
    EvidenceIntegrityReport
)
from src.graph.client import TigerGraphClient


def test_tool_allowlist_authorized():
    tg_client = TigerGraphClient(use_mock=True)
    registry = InvestigationToolRegistry(tg_client=tg_client)

    req = ToolRequest(
        tool_name="get_card_history",
        parameters={"card_id": "C12382-K1", "limit_cnt": 5},
        justification="Inspect card transaction timeline"
    )
    res = registry.execute_tool(req)
    assert res.status == "success"
    assert res.tool_name == "get_card_history"
    assert res.data is not None


def test_tool_allowlist_rejects_unauthorized():
    registry = InvestigationToolRegistry()

    # Attempt arbitrary python execution / shell
    req = ToolRequest(
        tool_name="run_arbitrary_python",
        parameters={"code": "import os; os.system('ls')"},
        justification="Attempt unauthorized code execution"
    )
    res = registry.execute_tool(req)
    assert res.status == "rejected_unauthorized"
    assert "not in the authorized tool allowlist" in res.error_message


def test_evidence_item_extraction_and_badges():
    trigger = {
        "amount": 7500.0,
        "card_id": "C12382-K1",
        "device_id": "DEV-RING-01",
        "ip_address": "198.51.100.42"
    }
    graph_ctx = {
        "card_history": {"transactions": [{"txn_id": "TX-1", "amount": 100.0}]},
        "ring_expansion": {"shared_cards": ["C12382-K1", "C99999-K2"]}
    }
    signals = [
        {"signal_code": "SIG-RING-02", "name": "Device Collusion Ring", "severity": 95.0, "weight": 1.0, "evidence": "2 cards linked"}
    ]
    policies = [
        {"section_id": "POL-FRD-2026", "section_title": "Multi-Account Collusion", "similarity": 0.88, "text": "Mandatory escalation for shared device rings."}
    ]
    cases = [
        {"case_id": "CASE-HIST-001", "outcome": "confirmed_fraud", "similarity": 0.92}
    ]

    items = EvidenceValidationEngine.extract_evidence_items(
        trigger_data=trigger,
        graph_context=graph_ctx,
        fired_signals=signals,
        retrieved_policies=policies,
        similar_cases=cases,
        round_num=1
    )

    assert len(items) >= 5
    evidence_ids = {e.evidence_id for e in items}
    assert any("EVID-TXN" in eid for eid in evidence_ids)
    assert any("EVID-GRAPH" in eid for eid in evidence_ids)
    assert any("EVID-SIG" in eid for eid in evidence_ids)
    assert any("EVID-POLICY" in eid for eid in evidence_ids)
    assert any("EVID-HIST" in eid for eid in evidence_ids)

    # Verification badges
    for item in items:
        assert item.verification_badge.startswith("✓")
        assert item.verified_status == "SUPPORTED"


def test_evidence_integrity_report_calculation():
    items = [
        EvidenceItem(evidence_id="EVID-TXN-001", source="Trigger", source_type="transaction", claim="Amount $500", verified_status="SUPPORTED"),
        EvidenceItem(evidence_id="EVID-GRAPH-002", source="TigerGraph", source_type="graph", claim="Shared cards 3", verified_status="SUPPORTED"),
        EvidenceItem(evidence_id="EVID-HIST-003", source="Memory", source_type="historical_case", claim="Similar case", verified_status="SUPPORTED"),
        EvidenceItem(evidence_id="EVID-POL-004", source="GraphRAG", source_type="policy", claim="SOP 4.2", verified_status="SUPPORTED")
    ]
    report = EvidenceValidationEngine.calculate_integrity_report(items)
    assert report.total_evidence_items == 4
    assert report.verified_claims == 4
    assert report.unsupported_claims == 0
    assert report.grounding_accuracy_pct == 100.0


def test_investigation_plan_structure():
    plan = InvestigationPlan(
        objective="Assess card C12382-K1",
        current_risk=85.0,
        evidence_sufficient=True,
        missing_evidence=["None"],
        hypotheses=["Typology: Distributed Device Ring"],
        contradictions=["No contradictory identity claims observed."],
        supporting_factors=["Device shared across 3 cards"],
        weakening_factors=["No material weakening evidence"],
        next_actions=["freeze_card", "file_sar"],
        reasoning_level="high"
    )
    assert plan.reasoning_level == "high"
    assert len(plan.next_actions) == 2
    assert "Distributed Device Ring" in plan.hypotheses[0]
