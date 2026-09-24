"""
Unit Tests for Evidence Integrity, Authentic Provenance, and Zero Synthetic Fallbacks.
"""

import pytest
from src.agent.state import InvestigationState
from dashboard.evidence_panel import (
    extract_why_flagged_breakdown,
    extract_risk_evolution,
    build_policy_grounding_chain,
    get_why_graph_comparison,
    build_evidence_provenance
)
from src.detection.scoring import RiskEngine


def test_orchestrator_persists_assessment_history():
    from src.agent.orchestrator import FraudInvestigationOrchestrator
    from src.graph.client import TigerGraphClient

    tg_client = TigerGraphClient(use_mock=True)
    orchestrator = FraudInvestigationOrchestrator(tg_client=tg_client)

    trigger = {
        "benchmark_id": "BM-001",
        "card_id": "CARD-2001",
        "account_id": "ACC-8001",
        "amount": 7500.0,
        "device_id": "DEV-RING-X9",
        "ip_address": "198.51.100.42",
        "trigger_type": "device_ring",
        "description": "High value purchase on known device ring"
    }

    state = orchestrator.investigate(trigger, case_id="CASE-INTEGRITY-01")
    assert len(state.assessment_history) >= 1
    assert state.assessment_history[0]["round"] == 1
    assert "risk_score" in state.assessment_history[0]["assessment"]
    assert state.assessment_history[0]["assessment"]["risk_score"] == state.initial_assessment["risk_score"]
    assert len(state.executed_queries) >= 3
    assert "graph_queries" in state.step_latencies_ms
    assert len(state.evidence_items) > 0
    assert state.integrity_report["verified_claims"] > 0


def test_risk_evolution_two_rounds():
    mock_state = InvestigationState(
        case_id="BM-001",
        trigger_data={},
        risk_score=92.0,
        confidence=0.88,
        uncertainty=0.12,
        current_round=2,
        assessment_history=[
            {
                "round": 1,
                "assessment": {"risk_score": 76.0, "confidence": 0.65, "uncertainty": 0.35},
                "reason": "Round 1 evaluation"
            },
            {
                "round": 2,
                "assessment": {"risk_score": 92.0, "confidence": 0.88, "uncertainty": 0.12},
                "reason": "Round 2 deep evaluation"
            }
        ]
    )
    evo = extract_risk_evolution(mock_state)
    assert evo["has_deep_dive"] is True
    assert evo["round1_score"] == 76.0
    assert evo["round2_score"] == 92.0
    assert evo["delta"] == 16.0


def test_no_synthetic_policy_chain_fallback():
    mock_state = InvestigationState(
        case_id="BM-EMPTY",
        trigger_data={},
        fired_signals=[],
        retrieved_policies=[],
        similar_cases=[]
    )
    chain = build_policy_grounding_chain(mock_state)
    assert len(chain) == 1
    assert "No active fraud signal" in chain[0]["signal"]


def test_why_graph_factual_comparison():
    trigger = {"amount": 2500.0, "card_id": "C9999", "account_id": "A111", "device_id": "DEV-01"}
    mock_state = InvestigationState(
        case_id="BM-TEST",
        trigger_data=trigger,
        risk_score=88.0,
        risk_tier="HIGH",
        current_round=1,
        fired_signals=[{"name": "Device Ring", "signal_code": "SIG-RING-02", "severity": 90, "weight": 1.0}],
        graph_context={
            "ring_expansion": {"shared_cards": ["C9999", "C8888"], "devices": ["DEV-01"]},
            "entity_links": {"cards": ["C9999"], "devices": ["DEV-01"]},
            "closed_cases": [{"case_id": "HIST-01"}]
        }
    )
    comp = get_why_graph_comparison(trigger, mock_state)
    assert "tabular" in comp
    assert "graph" in comp
    assert comp["graph"]["risk_verdict"] == "HIGH RISK (88/100)"


def test_evidence_provenance():
    trigger = {"card_id": "CARD-01", "amount": 1000.0}
    mock_state = InvestigationState(
        case_id="CASE-PROV",
        trigger_data=trigger,
        executed_queries=[
            {"query_name": "card_history", "params": {"target_card": "CARD-01"}, "hop_depth": 1, "round": 1}
        ],
        fired_signals=[{"name": "Velocity", "signal_code": "SIG-VEL-01", "severity": 80, "weight": 1.0}],
        retrieved_policies=[{"section_title": "Velocity Rules", "section_id": "POL-VEL", "similarity": 0.85}],
        similar_cases=[{"case_id": "CASE-PAST", "outcome": "confirmed_fraud", "similarity": 0.90}]
    )
    prov = build_evidence_provenance(mock_state, trigger)
    assert len(prov) == 4
    sources = {p["source"] for p in prov}
    assert "TigerGraph (GSQL)" in sources
    assert "Deterministic RiskEngine" in sources
