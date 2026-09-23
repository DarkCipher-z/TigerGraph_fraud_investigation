"""
Configuration management for TigerGraph Agentic Fraud Investigation.
Handles environment variable loading, API credentials, thresholds, and fallback configurations.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root if present
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

# TigerGraph Settings
TG_HOST = os.getenv("TG_HOST", "http://127.0.0.1:9000")
TG_USERNAME = os.getenv("TG_USERNAME", "tigergraph")
TG_PASSWORD = os.getenv("TG_PASSWORD", "tigergraph")
TG_GRAPH = os.getenv("TG_GRAPH", "FraudGraph")
TG_SECRET = os.getenv("TG_SECRET", "")
TG_API_TOKEN = os.getenv("TG_API_TOKEN", "")
TG_USE_MOCK = os.getenv("TG_USE_MOCK", "true").lower() in ("true", "1", "yes")

# Supabase Settings
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

# Google AI Studio / Gemini Settings
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "models/text-embedding-004")

# Groq Settings
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Agent & Risk Scoring Thresholds
RISK_THRESHOLD_HIGH = float(os.getenv("RISK_THRESHOLD_HIGH", "75.0"))
RISK_THRESHOLD_LOW = float(os.getenv("RISK_THRESHOLD_LOW", "35.0"))
CONFIDENCE_THRESHOLD_ACT = float(os.getenv("CONFIDENCE_THRESHOLD_ACT", "0.75"))
UNCERTAINTY_EVIDENCE_REQ = float(os.getenv("UNCERTAINTY_EVIDENCE_REQ", "0.30"))
MAX_INVESTIGATION_ROUNDS = int(os.getenv("MAX_INVESTIGATION_ROUNDS", "2"))
SAR_MIN_AMOUNT_THRESHOLD = float(os.getenv("SAR_MIN_AMOUNT_THRESHOLD", "5000.0"))

# LLM Fallback Order
LLM_FALLBACK_CHAIN = [
    s.strip().lower() for s in os.getenv("LLM_FALLBACK_CHAIN", "groq,gemini,deterministic").split(",")
]

# Action definitions
CRITICAL_ACTIONS = {"block_account", "file_sar", "freeze_card", "report_to_fiu"}
STANDARD_ACTIONS = {"step_up_mfa", "flag_for_review", "notify_customer", "allow_transaction"}
