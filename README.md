# 🛡️ TigerGraph Agentic Fraud Investigation (HHGOA)
> **Autonomous, Graph-Grounded Financial Crime & Fraud Intelligence Engine**
> **Infrastructure Cost:** $0.00 (100% Free Tier Architecture)

---

## 🌟 Overview

The **TigerGraph Agentic Fraud Investigation System** is a production-grade Financial Intelligence Unit (FIU) command center. It turns one suspicious transaction trigger into an explainable, graph-grounded investigation:

> *"Give us one suspicious transaction. We uncover the connected fraud network, gather additional evidence, explain why the transaction is suspicious, update the risk as evidence changes, and route consequential actions through human approval."*

It integrates:
- **TigerGraph Multi-Hop Graph Analytics (GSQL)** (`card_history`, `entity_links`, `ring_expand`, `closed_cases`, `recurring_devices`)
- **8-Step Autonomous Investigation Orchestrator** with dynamic uncertainty evidence loops
- **Deterministic Risk Scoring & Grounded Signal Decomposition** (authoritative scoring engine)
- **GraphRAG Compliance Policy Grounding** (`bank_fraud_policy.md` chunked via semantic vector retrieval)
- **Hybrid Case Memory** (combining topological overlap with cosine similarity over 5,570 closed cases)
- **3-Tier Resilient Reasoning Circuit Breaker** (Groq Llama 3.3 70B $\rightarrow$ Google Gemini Flash $\rightarrow$ Deterministic Rule Engine)
- **Human-in-the-Loop (HITL) Governance** with audit logging for consequential actions (account freezes, card blocks)
- **Draft FinCEN SAR Narrative Generation** (7-point regulatory draft for compliance officer review)
- **Interactive Command Center Dashboard** (Streamlit with real-time Plotly graph network, hop controls, ring isolation, and money flow trace)

---

## 🏗️ Architecture at a Glance

```text
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
│  GSQL Queries│ │ (7 Detectors) │ │  (pgvector)  │ │(Hybrid Match)│
└──────────────┘ └───────────────┘ └──────────────┘ └──────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │   Deterministic RiskEngine       │
        │   Weighted Signal Decomposition  │
        └──────────────┬───────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │ Resilient Multi-Tier LLM Chain   │
        │ Groq 70B -> Gemini -> RuleEngine │
        │ (Explains evidence, no score mod)│
        └──────────────┬───────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │ Governance, SAR & Action Audit   │
        │ Human-in-the-Loop Gating         │
        └──────────────┬───────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────┐
        │ FIU Command Center Dashboard     │
        │ (Real Graph, Rings, Audit Trail) │
        └──────────────────────────────────┘
```

---

## 🚀 Quickstart & Installation

### 1. Clone & Setup Environment
```powershell
git clone https://github.com/DarkCipher-z/TigerGraph_fraud_investigation.git
cd TigerGraph_fraud_investigation
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` (or run out-of-the-box in $0.00 mock mode):
```powershell
cp .env.example .env
```

### 3. Run Automated Tests (18 Passed)
```powershell
python -m pytest tests/ -v
```

### 4. Run the 20-Case Benchmark Suite
```powershell
python benchmark/run_benchmark.py --backend mock
```
Processes all 20 official benchmark test cases and generates structured JSON outputs in `benchmark/outputs/`.

### 5. Launch the FIU Command Center Dashboard
```powershell
streamlit run dashboard/app.py
```
Or view the live cloud deployment: **[Streamlit Community Cloud Deployment](https://tigergraphfraudinvestigation-dbshdqupegxrfbi8zqv8wh.streamlit.app/)**

---

## 📊 Core Features & Capabilities

1. **TigerGraph GSQL Engine**:
   - `card_history`: Gathers recent transaction and device timeline.
   - `entity_links`: Explores 1-hop and 2-hop connected accounts, devices, and IPs.
   - `ring_expand`: Discovers multi-card syndicates across shared hardware fingerprints.
   - `closed_cases`: Traverses graph to find past fraud dispositions on shared entities.
   - `recurring_devices`: Unsupervised community detection for multi-card clusters.

2. **Pattern Detection Layer (7 Heuristic Detectors)**:
   - `RING-02`: Distributed Device Rings & Rooted Emulators.
   - `ATO-03`: Account Takeover & Suspicious Credential Mutex.
   - `TEST-04`: Automated Bot Card Testing (BIN Attacks).
   - `VEL-01`: Rapid Transaction Velocity Bursts.
   - `GEO-05`: Impossible Travel Geovelocity Departure.
   - `AMT-HIGH`: High-value Anomaly & SAR Threshold ($5,000+).
   - `SIG-REP-01`: Customer Dispute & Analyst Escalations.

3. **GraphRAG & Policy Grounding**:
   - Chunks bank SOP documents and regulatory mandates (`bank_fraud_policy.md` / `POL-FRD-2026`).
   - Semantically retrieves policy rules using `text-embedding-004` and cosine similarity.

4. **Hybrid Case Memory**:
   - Combines graph topological overlap with vector cosine similarity over 5,570 closed cases.
   - Adjusts risk and confidence dynamically based on historical precedent outcomes.

5. **Multi-Tier LLM Circuit Breaker**:
   - Primary: **Groq (Llama 3.3 70B Versatile / Open Models)**
   - Secondary: **Google AI Studio (Gemini Flash Series)**
   - Tertiary: **Deterministic Rule Engine** (guarantees offline execution and graceful degradation when external API keys are invalid, rate-limited, or offline).
   - *LLM explains grounded evidence and proposes actions; it does not determine the numeric score.*

6. **Action Audit & Human-in-the-Loop Approval**:
   - Distinguishes between autonomous non-critical actions (`step_up_mfa`, `notify_customer`) and gated critical actions (`block_account`, `file_sar`, `freeze_card`).
   - Immutable audit logging with dual-stage routing (`pre_evidence` vs `post_evidence`).

7. **Draft FinCEN SAR Generator**:
   - Generates compliant 7-point regulatory narratives for transactions violating AML mandates.
   - Labeled clearly: *Draft narrative requiring human compliance review before filing.*

---

## 🔧 LLM Provider Troubleshooting & Diagnostics

- **Diagnostic Command**: Run `python scripts/check_llm_providers.py` to test live connectivity to all configured providers without exposing secrets.
- **Provider Authentication & Quota**:
  - `401 Unauthorized`: Root cause is an invalid or expired API key. Verify credentials in your `.env` or deployment environment secrets.
  - `429 Quota / Rate Limit`: Free-tier project quota exceeded for the requested model. The circuit breaker automatically routes to the Deterministic Rule Engine without failing.
- **Deployment Secrets**: Note that cloud platforms (Streamlit Community Cloud, Render) manage environment variables independently from your local `.env`. Ensure secrets are populated in each deployment dashboard.

---

## 📁 Repository Structure

```text
TigerGraph_fraud_investigation/
├── .env.example
├── README.md
├── ARCHITECTURE.md
├── DEMO_VIDEO_SCRIPT.md
├── requirements.txt
├── config.py
├── schema/
│   ├── schema.gsql                 # TigerGraph Graph Schema (8 vertices, 9 edges)
│   ├── queries.gsql                # 5 Installed GSQL Queries
│   └── supabase_schema.sql         # Postgres + pgvector + RLS Schema
├── data/
│   ├── bank_fraud_policy.md        # Official Bank SOP and Policy Rules
│   ├── sample_closed_cases.json    # Labeled Historical Cases
│   ├── case_pack.csv               # 20 Official Benchmark Triggers
│   ├── closed_cases_history.csv    # 5,566 Historical Case Precedents
│   └── synthetic_transactions.csv  # Realistic Transaction Dataset
├── src/
│   ├── graph/                      # TigerGraph client & mock backend
│   ├── detection/                  # Heuristic signal extractors & scoring
│   ├── rag/                        # Embeddings, Policy RAG, Case Memory
│   ├── llm/                        # Circuit breaker, prompts, parser
│   ├── agent/                      # 8-step orchestrator, state, audit log
│   └── sar/                        # FinCEN SAR narrative builder
├── dashboard/
│   ├── app.py                      # Production FIU Command Center Dashboard
│   ├── graph_builder.py            # Normalized graph evidence & BFS hop filter
│   └── evidence_panel.py           # Reconciled evidence scoring & evolution
├── benchmark/
│   ├── run_benchmark.py            # Benchmark execution script
│   └── outputs/                    # Output JSON answer files (20/20)
└── tests/                          # 18 Pytest unit & integration tests
```
