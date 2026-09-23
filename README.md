# 🛡️ TigerGraph Agentic Fraud Investigation (HHGOA)
> **Autonomous, Graph-Grounded Financial Crime & Fraud Intelligence Engine**
> **Infrastructure Cost:** $0.00 (100% Free Tier Architecture)

---

## 🌟 Overview

The **TigerGraph Agentic Fraud Investigation System** is a next-generation Financial Intelligence Unit (FIU) autonomous copilot. It combines **TigerGraph's multi-hop graph traversal (GSQL)** with **GraphRAG policy grounding (pgvector)**, **Case Memory**, a **3-tier Resilient LLM Circuit Breaker** (Groq Llama 3.3 70B $\rightarrow$ Google Gemini Flash $\rightarrow$ Deterministic Rule Engine), and an interactive **Streamlit Analyst Dashboard**.

---

## 🏗️ Architecture at a Glance

```
  [Suspicious Transaction Trigger / Benchmark Case]
                         │
                         ▼
        ┌──────────────────────────────────┐
        │  8-Step Agent Orchestrator       │
        └──────────────┬───────────────────┘
                       │
      ┌────────────────┼──────────────────┬─────────────────┐
      ▼                ▼                  ▼                 ▼
┌──────────────┐ ┌───────────────┐ ┌──────────────┐ ┌──────────────┐
│  TigerGraph  │ │ Pattern Layer │ │   GraphRAG   │ │ Case Memory  │
│  GSQL Queries│ │ (6 Detectors) │ │  (pgvector)  │ │(Hybrid Match)│
└──────────────┘ └───────────────┘ └──────────────┘ └──────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │ Resilient Multi-Tier LLM Chain   │
        │ Groq 70B -> Gemini -> RuleEngine │
        └──────────────┬───────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │ Governance, SAR & Action Audit   │
        │ Pre vs Post Evidence Dual Route  │
        └──────────────┬───────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │ Streamlit Analyst Dashboard & UI │
        └──────────────────────────────────┘
```

---

## 🚀 Quickstart & Installation

### 1. Clone & Setup Environment
```powershell
git clone <repo-url>
cd d:/TigerGraph_fraud_investigation
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and fill in your free tier API keys (or leave default to run in $0.00 mock mode):
```powershell
cp .env.example .env
```

### 3. Run Automated Tests
```powershell
python -m pytest tests/ -v
```

### 4. Run the 20-Case Benchmark Suite
```powershell
python benchmark/run_benchmark.py --backend mock
```
This will process all 20 benchmark test cases and generate structured JSON outputs in `benchmark/outputs/`.

### 5. Launch the Streamlit Analyst Dashboard
```powershell
streamlit run dashboard/app.py
```

---

## 📊 Core Features & Capabilities

1. **TigerGraph GSQL Engine**:
   - `card_history`: Gathers recent transaction and device timeline.
   - `entity_links`: Explores 1-hop and 2-hop connected accounts, devices, and IPs.
   - `ring_expand`: Discovers multi-card syndicates across shared hardware fingerprints.
   - `closed_cases`: Traverses graph to find past fraud dispositions on shared entities.
   - `recurring_devices`: Unsupervised community detection for multi-card clusters.

2. **Pattern Detection Layer (6 Heuristic Detectors)**:
   - `RING-02`: Distributed Device Rings & Rooted Emulators.
   - `ATO-03`: Account Takeover & Suspicious Credential Mutex.
   - `TEST-04`: Automated Bot Card Testing (BIN Attacks).
   - `VEL-01`: Rapid Transaction Velocity Bursts.
   - `GEO-05`: Impossible Travel Geovelocity Departure.
   - `AMT-HIGH`: High-value Anomaly & SAR Threshold ($5,000+).

3. **GraphRAG & Policy Grounding**:
   - Chunks bank SOP documents and regulatory mandates (`POL-FRD-2026`).
   - Semantically retrieves policy rules using `text-embedding-004` and cosine similarity.

4. **Hybrid Case Memory**:
   - Combines graph topological overlap with vector cosine similarity on closed cases.
   - Adjusts risk and confidence dynamically based on historical precedent outcomes.

5. **Multi-Tier LLM Circuit Breaker**:
   - Primary: **Groq (Llama 3.3 70B Versatile)**
   - Secondary: **Google AI Studio (Gemini 2.5/3.7 Flash)**
   - Tertiary: **Deterministic Rule Engine** (guarantees 100% uptime and offline execution).

6. **Action Audit & Human-in-the-Loop Approval**:
   - Distinguishes between autonomous non-critical actions (`step_up_mfa`, `notify_customer`) and gated critical actions (`block_account`, `file_sar`, `freeze_card`).
   - Immutable audit logging with dual-stage routing (`pre_evidence` vs `post_evidence`).

7. **FinCEN SAR Generator**:
   - Generates compliant 7-point regulatory narratives for transactions violating AML mandates.

---

## 📁 Repository Structure

```
d:/TigerGraph_fraud_investigation/
├── .env.example
├── README.md
├── ARCHITECTURE.md
├── requirements.txt
├── config.py
├── schema/
│   ├── schema.gsql                 # TigerGraph Graph Schema
│   ├── queries.gsql                # 5 Installed GSQL Queries
│   └── supabase_schema.sql         # Postgres + pgvector + RLS Schema
├── data/
│   ├── bank_fraud_policy.md        # Official Bank SOP and Policy Rules
│   ├── sample_closed_cases.json    # Labeled Historical Cases
│   ├── benchmark_triggers.json     # 20 Official Benchmark Triggers
│   └── synthetic_transactions.csv  # Realistic Transaction Dataset
├── src/
│   ├── graph/                      # TigerGraph client & mock backend
│   ├── detection/                  # Heuristic signal extractors & scoring
│   ├── rag/                        # Embeddings, Policy RAG, Case Memory
│   ├── llm/                        # Circuit breaker, prompts, parser
│   ├── agent/                      # 8-step orchestrator, state, audit log
│   └── sar/                        # FinCEN SAR narrative builder
├── dashboard/
│   └── app.py                      # Interactive Streamlit Analyst Dashboard
├── benchmark/
│   ├── run_benchmark.py            # Benchmark execution script
│   └── outputs/                    # Output JSON answer files
└── tests/                          # Pytest unit & integration test suite
```
