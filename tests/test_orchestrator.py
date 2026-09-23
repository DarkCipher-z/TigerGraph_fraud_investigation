"""
End-to-End Tests for Master Investigation Orchestrator.
"""

from src.agent.orchestrator import FraudInvestigationOrchestrator
from src.graph.client import TigerGraphClient


def test_orchestrator_fraud_ring_case():
    tg_client = TigerGraphClient(use_mock=True)
    orchestrator = FraudInvestigationOrchestrator(tg_client=tg_client)
    
    trigger = {
        "benchmark_id": "BM-TEST-01",
        "card_id": "CARD-2001",
        "account_id": "ACC-8001",
        "amount": 7500.0,
        "device_id": "DEV-RING-X9",
        "ip_address": "198.51.100.42",
        "trigger_type": "device_ring",
        "description": "High value purchase on known device ring"
    }
    
    state = orchestrator.investigate(trigger, case_id="CASE-TEST-RING")
    
    assert state.case_id == "CASE-TEST-RING"
    assert len(state.events) == 8
    assert state.risk_score >= 75.0
    assert state.final_disposition in ["confirmed_fraud", "escalate_to_analyst"]
    assert state.requires_sar is True
    assert state.sar_narrative is not None
    assert len(state.actions_post_evidence) > 0


def test_orchestrator_benign_case():
    tg_client = TigerGraphClient(use_mock=True)
    orchestrator = FraudInvestigationOrchestrator(tg_client=tg_client)
    
    trigger = {
        "benchmark_id": "BM-TEST-02",
        "card_id": "CARD-2008",
        "account_id": "ACC-8008",
        "amount": 65.40,
        "device_id": "DEV-HOME-MAC",
        "ip_address": "192.0.2.1",
        "trigger_type": "benign_regular",
        "description": "Weekly grocery purchase"
    }
    
    state = orchestrator.investigate(trigger, case_id="CASE-TEST-BENIGN")
    
    assert state.risk_score < 35.0
    assert state.risk_tier == "LOW"
    assert state.final_disposition == "cleared_benign"
    assert state.requires_sar is False
