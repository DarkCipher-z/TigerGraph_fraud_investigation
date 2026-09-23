"""
Unit tests for GraphRAG Policy Retrieval and Embeddings.
"""

from src.rag.policy_retriever import PolicyRetriever
from src.rag.embeddings import EmbeddingService


def test_embedding_generation():
    service = EmbeddingService()
    vec = service.embed_text("Suspicious device ring shared across accounts")
    assert len(vec) == 768
    assert isinstance(vec[0], float)


def test_policy_retrieval_sar():
    retriever = PolicyRetriever()
    results = retriever.retrieve("SAR $5,000 threshold compliance FinCEN", top_k=2)
    assert len(results) > 0
    assert any("SAR" in r["section_title"] or r["mandatory_sar"] for r in results)


def test_policy_retrieval_ring():
    retriever = PolicyRetriever()
    results = retriever.retrieve("device ring shared emulator hardware fingerprint", top_k=2)
    assert len(results) > 0
    assert any("Device Ring" in r["section_title"] or "RING" in r["content"] for r in results)
