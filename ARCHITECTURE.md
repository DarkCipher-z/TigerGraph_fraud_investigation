# 🏛️ Technical Architecture & System Design
**TigerGraph Agentic Fraud Investigation (HHGOA)**

---

## 1. 8-Step Autonomous Investigation Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Trg as Event Trigger / Benchmark
    participant Orch as 8-Step Orchestrator
    participant TG as TigerGraph (GSQL)
    participant Det as Pattern Detectors
    participant RAG as GraphRAG Policy Store
    participant Mem as Hybrid Case Memory
    participant LLM as Multi-Tier LLM Chain
    participant Aud as Action Audit Logger
    actor Analyst as Compliance Officer

    Trg->>Orch: Ingest Transaction Event
    Orch->>TG: Step 2: GSQL Expansion (card_history, entity_links, ring_expand)
    TG-->>Orch: Subgraph Neighborhood
    Orch->>Det: Step 3: Extract Pattern Signals (6 Detectors)
    Det-->>Orch: Fired Signals & Weights
    Orch->>RAG: Step 4: Vector Policy Match (text-embedding-004)
    RAG-->>Orch: Grounded Policy Chunks
    Orch->>Mem: Step 5: Hybrid Memory Lookup (Graph + Cosine)
    Mem-->>Orch: Relevant Past Case Dispositions
    Orch->>Aud: Step 6: Initial Assessment & Pre-Evidence Action Routing
    alt Uncertainty > Threshold (0.30)
        Orch->>TG: Step 7: Deep Evidence Gathering (Round 2 Expansion)
        TG-->>Orch: Deep Subgraph Context
    end
    Orch->>LLM: Step 8: Multi-Tier Synthesis (Groq -> Gemini -> Fallback)
    LLM-->>Orch: Structured Decision & Rationale
    Orch->>Aud: Post-Evidence Routing (Critical Actions Gated)
    alt Action is Critical (block_account, file_sar)
        Aud->>Analyst: Queue in HITL Approval Dashboard
        Analyst->>Aud: Sign-off & Execute
    end
    Orch->>TG: Upsert FraudCase Vertex
```

---

## 2. Mathematical Scoring Models

### 2.1 Weighted Risk Score
Given a set of fired signals $S = \{s_1, s_2, \dots, s_k\}$, each with severity $\sigma(s_i) \in [0, 100]$ and weight $w(s_i) > 0$:

$$\text{RawRisk}(S) = \frac{\sum_{i=1}^k \sigma(s_i) \cdot w(s_i)}{\sum_{i=1}^k w(s_i)}$$

Historical case memory adjustment with precedent similarity $\text{sim}(c_j)$:

$$\Delta_{\text{mem}} = \sum_{j \in \text{Precedents}} \begin{cases} +10 \cdot \text{sim}(c_j) & \text{if outcome} = \text{confirmed\_fraud} \\ -8 \cdot \text{sim}(c_j) & \text{if outcome} = \text{cleared\_benign} \end{cases}$$

$$\text{RiskScore} = \text{clip}(\text{RawRisk}(S) + \Delta_{\text{mem}}, 5.0, 99.0)$$

### 2.2 Confidence & Uncertainty Formulation
Confidence aggregates signal counts, policy grounding relevance, and iterative verification rounds:

$$\text{Confidence} = \text{clip}\left(0.60 + \min(0.25, |S| \times 0.08) + \min(0.10, |P| \times 0.03) + \mathbb{I}_{\text{round}>1} \times 0.08, 0.40, 0.98\right)$$

Uncertainty is elevated when the decision lies on the classification boundary ($\text{Risk} \approx 50$) or when confidence is depressed:

$$d_{\text{boundary}} = \frac{|\text{RiskScore} - 50.0|}{50.0}$$
$$\text{Uncertainty} = \text{clip}\left((1.0 - \text{Confidence}) \times 0.7 + (1.0 - d_{\text{boundary}}) \times 0.3, 0.05, 0.95\right)$$

---

## 3. Resilient Multi-Tier Circuit Breaker

```mermaid
stateDiagram-v2
    [*] --> Primary_Groq
    Primary_Groq --> Secondary_Gemini : Timeout / Rate Limit / Error
    Primary_Groq --> Success : 200 OK
    Secondary_Gemini --> Tertiary_RuleEngine : API Key Missing / Failure
    Secondary_Gemini --> Success : 200 OK
    Tertiary_RuleEngine --> Success : Deterministic Output
    Success --> [*]
```

---

## 4. GSQL Query Specifications

| Query Name | Parameters | Purpose |
| :--- | :--- | :--- |
| `card_history` | `VERTEX<Card> target_card, INT limit_cnt` | Fetches temporal sequence of transactions, devices, IPs, and merchants |
| `entity_links` | `VERTEX<Card> target_card` | Explores 1-hop and 2-hop connected accounts, cards, devices, and IPs |
| `ring_expand` | `VERTEX<Device> seed_device, INT max_depth` | Traverses multi-card sharing rings across shared hardware fingerprints |
| `closed_cases` | `VERTEX<Card> target_card` | Retrieves historical closed cases touching any connected entity in graph |
| `recurring_devices`| `INT min_cards` | Performs community detection for devices shared across $\ge k$ distinct cards |
