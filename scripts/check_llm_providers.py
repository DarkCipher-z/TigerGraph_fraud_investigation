"""
Diagnostic script to verify LLM providers connectivity.
Tests Gemini, Groq, and the Deterministic Rule Engine safely without exposing secrets.
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from src.llm.circuit_breaker import ResilientLLMChain

def test_gemini():
    model = config.GEMINI_MODEL
    if not config.GEMINI_API_KEY:
        return model, "Not Configured (Missing GEMINI_API_KEY)", "None"
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=config.GEMINI_API_KEY, transport="rest")
        m = genai.GenerativeModel(model)
        res = m.generate_content("Say OK in one word.")
        text = res.text.strip() if res and res.text else "OK"
        return model, "Connected (200 OK)", text.replace("\n", " ")[:60]
    except Exception as e:
        err_msg = str(e)
        if "404" in err_msg or "not found" in err_msg.lower():
            status = f"Failed (Model not found: {model})"
        elif "429" in err_msg or "quota" in err_msg.lower():
            status = "Rate Limited (429 Quota Exceeded)"
        elif "401" in err_msg or "unauthenticated" in err_msg.lower():
            status = "Authentication Failed (401 Invalid Key)"
        else:
            status = f"Failed ({type(e).__name__})"
        return model, status, "Error: " + err_msg.splitlines()[0][:80]

def test_groq():
    model = config.GROQ_MODEL
    if not config.GROQ_API_KEY:
        return model, "Not Configured (Missing GROQ_API_KEY)", "None"
    
    try:
        from groq import Groq
        client = Groq(api_key=config.GROQ_API_KEY)
        
        # Test configured model
        try:
            res = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Say OK in one word."}],
                max_tokens=10
            )
            text = res.choices[0].message.content.strip()
            return model, "Connected (200 OK)", text.replace("\n", " ")[:60]
        except Exception as model_err:
            err_str = str(model_err)
            if "model_not_found" in err_str or "404" in err_str:
                # Discover what models are available on this key
                try:
                    avail = [m.id for m in client.models.list().data if "gpt" in m.id or "qwen" in m.id or "llama" in m.id]
                    fallback_model = avail[0] if avail else "openai/gpt-oss-120b"
                    res = client.chat.completions.create(
                        model=fallback_model,
                        messages=[{"role": "user", "content": "Say OK in one word."}],
                        max_tokens=10
                    )
                    text = res.choices[0].message.content.strip() or "OK"
                    return f"{model} (Active: {fallback_model})", f"Connected via {fallback_model} (404 on {model})", text.replace("\n", " ")[:60]
                except Exception as inner:
                    return model, f"Model Not Found (404 on {model})", "Error: " + err_str.splitlines()[0][:80]
            elif "401" in err_str or "invalid_api_key" in err_str:
                return model, "Authentication Failed (401 Invalid Key)", "Error: Invalid API Key"
            else:
                return model, f"Failed ({type(model_err).__name__})", "Error: " + err_str.splitlines()[0][:80]
    except Exception as e:
        return model, f"Failed ({type(e).__name__})", str(e)[:80]

def test_deterministic():
    chain = ResilientLLMChain()
    text = chain._deterministic_fallback_response("Trigger: SIG-RING-02 Distributed Device Ring")
    if "confirmed_fraud" in text and "freeze_card" in text:
        return "Operational (Deterministic Rule Engine available)"
    return "Degraded"

def main():
    print("=" * 60)
    print("TIGERGRAPH AGENTIC FRAUD INVESTIGATION - LLM PROVIDER CHECK")
    print("=" * 60)
    
    gem_model, gem_conn, gem_resp = test_gemini()
    print("\nGemini:")
    print(f"Model: {gem_model}")
    print(f"Connectivity: {gem_conn}")
    print(f"Response: {gem_resp}")
    
    groq_model, groq_conn, groq_resp = test_groq()
    print("\nGroq:")
    print(f"Model: {groq_model}")
    print(f"Connectivity: {groq_conn}")
    print(f"Response: {groq_resp}")
    
    det_status = test_deterministic()
    print("\nDeterministic Engine:")
    print(f"Status: {det_status}")
    
    print("\nProvider chain:\n")
    print("Groq -> Gemini -> Deterministic")
    print("=" * 60)

if __name__ == "__main__":
    main()
