"""
Unit tests for Pattern Detection Layer.
"""

import pytest
from src.graph.client import TigerGraphClient
from src.detection.signals import SignalDetector
from src.detection.scoring import RiskEngine


@pytest.fixture
def setup_detection():
    tg_client = TigerGraphClient(use_mock=True)
    detector = SignalDetector(tg_client)
    return tg_client, detector


def test_device_ring_detection(setup_detection):
    tg_client, detector = setup_detection
    trigger = {
        "card_id": "CARD-2001",
        "device_id": "DEV-RING-X9",
        "amount": 2500.0,
        "trigger_type": "device_ring",
        "description": "Shared ring device"
    }
    graph_ctx = {"ring_expansion": tg_client.expand_ring("DEV-RING-X9")}
    signals = detector.extract_all_signals(trigger, graph_ctx)
    
    assert any(s["typology_code"] == "RING-02" for s in signals)


def test_card_testing_detection(setup_detection):
    tg_client, detector = setup_detection
    trigger = {
        "card_id": "CARD-1002",
        "device_id": "DEV-BOT-01",
        "amount": 1500.0,
        "trigger_type": "card_testing",
        "description": "Card testing with micro authorizations"
    }
    graph_ctx = {"card_history": tg_client.get_card_history("CARD-1002")}
    signals = detector.extract_all_signals(trigger, graph_ctx)
    
    assert any(s["typology_code"] == "TEST-04" for s in signals)


def test_benign_evaluation(setup_detection):
    tg_client, detector = setup_detection
    trigger = {
        "card_id": "CARD-2008",
        "device_id": "DEV-HOME-MAC",
        "amount": 65.40,
        "trigger_type": "benign_regular",
        "description": "Regular groceries"
    }
    signals = detector.extract_all_signals(trigger, {})
    result = RiskEngine.evaluate(signals)
    
    assert result.risk_tier == "LOW"
    assert result.risk_score < 35.0
    assert not result.requires_evidence
