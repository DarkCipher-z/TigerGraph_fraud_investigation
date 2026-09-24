"""
Unit tests for TigerGraph Evidence Graph Builder & Explainer Panels
Validates graph normalization, hop depth truncation, trace to fraud pathfinding,
node inspection, money flow reconstruction, and mathematical signal deconstruction.
"""

import pytest
from dashboard.graph_builder import (
    normalize_graph_evidence,
    filter_subgraph_by_hops,
    find_trace_to_fraud_path,
    get_node_details,
    reconstruct_money_flow,
    extract_identity_collisions
)
from dashboard.evidence_panel import (
    extract_why_flagged_breakdown,
    extract_risk_evolution,
    build_policy_grounding_chain,
    get_why_graph_comparison
)
from src.agent.state import InvestigationState, CaseEvent, ProposedAction
from src.detection.scoring import RiskEngine


@pytest.fixture
def mock_graph_context():
    return {
        "card_history": {
            "transactions": [
                {"txn_id": "TX-101", "amount": 2850.0, "merchant": "ElectroMart", "timestamp": "2026-09-24 09:41:00"},
                {"txn_id": "TX-102", "amount": 45.0, "merchant": "Cafe Express", "timestamp": "2026-09-24 09:43:00"}
            ]
        },
        "entity_links": {
            "devices": [{"device_id": "DEV-TEST-01", "is_rooted": True, "is_vpn": True}],
            "cards": ["C99999-K1"]
        },
        "ring_expand": {
            "shared_cards": ["C99999-K1", "C88888-K2"],
            "devices": ["DEV-RING-X9"]
        },
        "closed_cases": [
            {"case_id": "CASE-HIST-001", "pattern": "Device Ring", "exposure_usd": 15400.0}
        ]
    }


@pytest.fixture
def mock_trigger():
    return {
        "benchmark_id": "BM-001",
        "card_id": "C12382-K1",
        "account_id": "ACC-9921",
        "amount": 2850.0,
        "device_id": "DEV-RING-X9",
        "ip_address": "198.51.100.42",
        "trigger_text": "Device DEV-RING-X9 linked to 3 distinct cards"
    }


def test_normalize_graph_evidence(mock_graph_context, mock_trigger):
    result = normalize_graph_evidence(mock_graph_context, mock_trigger, max_hops=2)
    assert "nodes" in result
    assert "edges" in result
    assert result["total_nodes"] > 0
    assert result["total_edges"] > 0
    assert result["ring_detected"] is True
    
    # Check node attributes and evidence lineage
    node_types = {n["type"] for n in result["nodes"]}
    assert "Card" in node_types
    assert "Device" in node_types
    assert "FraudCase" in node_types

    # Verify all nodes have evidence_source
    for n in result["nodes"]:
        assert "evidence_source" in n
        assert "attributes" in n


def test_hop_depth_filtering(mock_graph_context, mock_trigger):
    res_1hop = normalize_graph_evidence(mock_graph_context, mock_trigger, max_hops=1)
    res_3hops = normalize_graph_evidence(mock_graph_context, mock_trigger, max_hops=3)
    assert res_1hop["total_nodes"] <= res_3hops["total_nodes"]


def test_trace_to_fraud_path(mock_graph_context, mock_trigger):
    graph_data = normalize_graph_evidence(mock_graph_context, mock_trigger, max_hops=2)
    path = find_trace_to_fraud_path(graph_data)
    assert len(path) >= 2
    assert path[0] == mock_trigger["card_id"]
    assert "CASE-HIST-001" in path[-1]


def test_get_node_details(mock_graph_context, mock_trigger):
    graph_data = normalize_graph_evidence(mock_graph_context, mock_trigger, max_hops=2)
    details = get_node_details(graph_data, mock_trigger["card_id"])
    assert details is not None
    assert details["node"]["id"] == mock_trigger["card_id"]
    assert details["connected_count"] > 0
    assert "evidence_source" in details


def test_reconstruct_money_flow(mock_graph_context, mock_trigger):
    flow = reconstruct_money_flow(mock_graph_context, mock_trigger)
    assert "flows" in flow
    assert len(flow["flows"]) >= 2
    assert flow["total_volume"] > 2800.0


def test_identity_collisions(mock_graph_context, mock_trigger):
    collision = extract_identity_collisions(mock_graph_context, mock_trigger)
    assert collision["collision_detected"] is True
    assert len(collision["identities"]) >= 2


def test_why_flagged_breakdown_reconciliation():
    signals = [
        {"signal_code": "SIG-RING-02", "name": "Distributed Device Ring", "severity": 95.0, "weight": 1.0, "evidence": "3 cards linked"},
        {"signal_code": "SIG-VEL-01", "name": "Velocity Burst", "severity": 85.0, "weight": 0.8, "evidence": "Rapid transactions"}
    ]
    prior = [
        {"case_id": "CASE-HIST-001", "similarity": 0.85, "outcome": "confirmed_fraud"}
    ]

    eval_res = RiskEngine.evaluate(signals=signals, prior_cases=prior)
    assert len(eval_res.signal_contributions) == 2
    assert eval_res.memory_adjustment > 0
    # Reconciliation test: sum of contributions equals raw_risk
    assert round(sum(sc["contribution"] for sc in eval_res.signal_contributions), 1) == round(eval_res.raw_risk, 1)

    mock_state = InvestigationState(
        case_id="BM-001",
        trigger_data={},
        graph_context={},
        fired_signals=signals,
        similar_cases=prior,
        risk_score=eval_res.risk_score,
        confidence=eval_res.confidence,
        uncertainty=eval_res.uncertainty,
        signal_contributions=eval_res.signal_contributions,
        memory_adjustment=eval_res.memory_adjustment,
        raw_risk=eval_res.raw_risk
    )
    breakdown = extract_why_flagged_breakdown(mock_state)
    assert "items" in breakdown
    assert len(breakdown["items"]) >= 2
    assert breakdown["final_risk"] == eval_res.risk_score


def test_risk_evolution():
    mock_state = InvestigationState(
        case_id="BM-001",
        trigger_data={},
        graph_context={},
        risk_score=95.0,
        confidence=0.85,
        uncertainty=0.15,
        initial_assessment={"risk_score": 80.0, "confidence": 0.65, "uncertainty": 0.35, "requires_evidence": True}
    )
    evo = extract_risk_evolution(mock_state)
    assert evo["final_score"] == 95.0
    assert evo["round1_score"] == 80.0
    assert evo["delta"] == 15.0
    assert evo["has_deep_dive"] is True
