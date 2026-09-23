"""
Unit tests for Case Memory Hybrid Retrieval.
"""

from src.graph.client import TigerGraphClient
from src.rag.case_memory import CaseMemoryService


def test_case_memory_retrieval():
    tg_client = TigerGraphClient(use_mock=True)
    memory = CaseMemoryService(tg_client=tg_client)
    
    # Query with known ring device DEV-RING-X9
    results = memory.retrieve_hybrid_precedents(
        card_id="CARD-1001",
        device_id="DEV-RING-X9",
        case_summary_query="Device ring fraud syndicate electronics purchases",
        top_k=2
    )
    
    assert len(results) > 0
    assert any(r["case_id"] == "CASE-HIST-001" for r in results)
    assert results[0]["is_graph_linked"] is True
