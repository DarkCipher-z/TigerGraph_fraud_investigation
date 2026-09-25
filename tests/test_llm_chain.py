"""
Unit tests for Resilient LLM Circuit Breaker.
"""

from src.llm.circuit_breaker import ResilientLLMChain
from src.llm.structured_parser import StructuredOutputParser


def test_circuit_breaker_deterministic_fallback():
    chain = ResilientLLMChain()
    # Prompt simulating a device ring case
    prompt = "Trigger: SIG-RING-02 Distributed Device Ring DEV-RING-X9 with multiple cards."
    
    text, provider, latency = chain.generate(prompt)
    assert text is not None
    assert latency >= 0
    assert provider.startswith("gemini_") or provider.startswith("groq_") or provider == "deterministic_rule_engine"
    
    parsed = StructuredOutputParser.parse_investigation_response(text)
    assert parsed is not None
    assert "recommended_disposition" in parsed
    assert "proposed_actions" in parsed
