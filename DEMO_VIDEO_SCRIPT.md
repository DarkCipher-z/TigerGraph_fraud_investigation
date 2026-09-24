# 🎬 Demo Video Script (3 Minutes)
**Project:** TigerGraph Agentic Fraud Investigation (HHGOA)  
**Target Duration:** ~3:00 to 3:30 Minutes  

---

## ⏱️ Video Breakdown Summary
- **0:00 – 0:30**: Problem Hook & Persistent Case Header (Detect)
- **0:30 – 1:00**: Real TigerGraph Evidence Network & Multi-Hop Traversal (Connect)
- **1:00 – 1:30**: "Why Flagged?" Grounded Signal Breakdown & Risk Evolution (Explain)
- **1:30 – 2:00**: "Why Graph?" Micro-View: Tabular vs TigerGraph Contrast
- **2:00 – 2:30**: Policy & Case Memory Chain + Entity Relationship Trace
- **2:30 – 3:00**: Human-in-the-Loop Governance & Draft FinCEN SAR (Decide & Audit)
- **3:00 – 3:30**: Benchmark Scorecard (20/20) & Summary

---

## 📝 Scene-by-Scene Script

---

### **Scene 1: Introduction & Case Header (0:00 – 0:30)**

**Visuals On Screen:**
- Start directly on the **Demo Mode: Fraud Command Center** (`streamlit run dashboard/app.py`).
- Highlight the **Persistent Case Header**:
  - `CASE BM-001`
  - `CRITICAL RISK: 99/100`
  - `CONFIDENCE: 77%`
  - `FINCEN SAR: DRAFT REQUIRED`
  - `Backend: MOCK GRAPH BACKEND / LIVE TIGERGRAPH CLOUD`

**Voiceover / Script:**
> *"Welcome to the **TigerGraph FIU Command Center**—an autonomous, graph-native fraud investigation system.*
>
> *Traditional tabular systems inspect transactions one by one, completely blind to coordinated fraud rings. Modern syndicates don't attack with one stolen card—they share rooted emulators, virtual devices, and money mule accounts across dozens of identities.*
>
> *Our system turns one suspicious transaction into an end-to-end graph investigation: we detect the trigger, uncover the hidden relationship network in TigerGraph, explain why it's fraudulent, track risk evolution, and route high-stakes actions through human approval."*

---

### **Scene 2: Real TigerGraph Evidence Network (0:30 – 1:00)**

**Visuals On Screen:**
- Focus on the **Center Column (Interactive Plotly Graph)**:
  - Concentric radial layout displaying Card (Cyan), Device (Red), Account (Green), and Fraud Precedents (Rose).
  - Click **`[ 🕸️ TRACE FRAUD RING ]`**: Watch non-ring nodes dim, isolating the shared device `DEV-RING-X9` and its 3 connected cards.
  - Click **`[ ⚡ TRACE TO FRAUD ]`**: A bright crimson path appears: `Card → Device → Shared Card → CASE-HIST-001`.
  - Open the **Node Inspector** dropdown and select `DEV-RING-X9` to inspect its rooted OS and emulator attributes.

**Voiceover / Script:**
> *"In the center is our **real TigerGraph evidence network**—generated directly from GSQL queries like `ring_expand`, `entity_links`, and `card_history`.*
>
> *Watch what happens when we click **Trace Fraud Ring**: the system isolates the coordinated hardware hub `DEV-RING-X9`, showing how 3 separate cards share the exact same rooted mobile device.*
>
> *Next, we click **Trace to Fraud**. TigerGraph executes a multi-hop shortest-path traversal, proving in milliseconds that this device directly links to a confirmed historical SAR filing, `CASE-HIST-001`."*

---

### **Scene 3: "Why Flagged?" & Risk Evolution (1:00 – 1:30)**

**Visuals On Screen:**
- Focus on the **Left Column ("Why Was This Case Flagged?")**:
  - Show the mathematical signal points: `+28.5 pts Distributed Device Ring`, `+25.0 pts Historical Precedent Match`.
  - Highlight the methodology note: *Risk is calculated strictly by the deterministic RiskEngine; LLM explains evidence.*
- Focus on the **Right Column ("Investigation Evolution")**:
  - Show `Round 1: Heuristic (84/100) → Round 2: Multi-Hop GSQL (99/100) [+15 pts]`.

**Voiceover / Script:**
> *"On the left is our **Why Flagged?** evidence panel. Crucially, these scores are NOT invented by an LLM hallucination—they are mathematically derived from our deterministic RiskEngine, showing the exact point contribution for each fired signal.*
>
> *On the right, we show **Investigation Evolution**. In Round 1, heuristic signals flagged a risk of 84. Because uncertainty exceeded 0.30, our agent autonomously triggered Round 2: a 3-hop GSQL ring expansion that discovered additional hardware collusion, escalating the final score to 99 with 77% confidence."*

---

### **Scene 4: "Why Graph?" Micro-View (1:30 – 2:00)**

**Visuals On Screen:**
- Scroll down and open the **"🔍 Why Graph? (Tabular vs TigerGraph)"** tab.
- Show the side-by-side comparison:
  - Left: *Traditional Row-Level SQL* rates the $2,850 transaction as Moderate/Low (35-45/100).
  - Right: *TigerGraph Multi-Hop Investigation* rates it as CRITICAL (99/100).

**Voiceover / Script:**
> *"Under the **Why Graph?** tab, we demonstrate the core value proposition for financial institutions.*
>
> *A traditional row-level SQL rule engine looks at this \$2,850 transaction and sees an active card at a normal retail merchant—it approves it.*
>
> *TigerGraph looks beyond the isolated transaction: it traverses multi-hop edges to uncover the shared hardware fingerprint, multiple card collisions, and links to prior fraud. Traditional row-level analysis sees the transaction; TigerGraph exposes the syndicate behind it."*

---

### **Scene 5: Entity Relationship Trace & Policy Grounding (2:00 – 2:30)**

**Visuals On Screen:**
- Click the **"💰 Entity Relationship & Transaction Trace"** tab.
  - Step 1: Card → Account ingress ($2,850).
  - Steps 2–4: Account → Merchant egress.
  - Show cycle detection summary.
- Switch to the **"👥 Identity Collision Radar"** tab, showing 3 customer profiles sharing one hardware device.

**Voiceover / Script:**
> *"Under **Entity Relationship Trace**, we reconstruct the chronological flow of transactions, verifying whether funds follow a linear settlement or a cyclic laundering loop.*
>
> *In our **Identity Collision Radar**, we instantly spot synthetic identity creation: multiple distinct customer accounts originating from one physical hardware device."*

---

### **Scene 6: Human-in-the-Loop & Draft SAR (2:30 – 3:00)**

**Visuals On Screen:**
- Click the **"⚖️ Action Decision & Human Governance"** tab.
  - Recommended Action: `FREEZE CARD → Target: C12382-K1`.
  - Status: `⏳ WAITING FOR HUMAN APPROVAL`.
  - Click **`[ APPROVE ]`**: Status instantly updates to `✅ APPROVED (Audit Event Recorded)`.
- Click the **"📑 Draft SAR Narrative"** tab.
  - Show the FinCEN 7-point regulatory draft.
  - Point out the disclaimer: *Draft narrative requiring human compliance review before filing.*
  - Show the **"Download Draft SAR (.txt)"** button.

**Voiceover / Script:**
> *"Now for governance. Our system operates under strict **Human-in-the-Loop compliance**.*
>
> *The AI agent proposes high-consequence actions like `freeze_card` and `file_sar`, but policy forbids autonomous execution. As an investigator, I review the grounded evidence and click **Approve**.*
>
> *Under **Draft SAR Narrative**, the system synthesizes a complete, FinCEN 111-compliant 7-point regulatory report, ready for compliance review and one-click export."*

---

### **Scene 7: Benchmark Scorecard & Conclusion (3:00 – 3:30)**

**Visuals On Screen:**
- In the sidebar, select **"📊 20-Case Benchmark Scorecard"**.
  - Show 20/20 cases processed, ~250ms average latency, and category breakdown.
- Highlight the live deployment URL and GitHub repository.

**Voiceover / Script:**
> *"Finally, in our **20-Case Benchmark Scorecard**, the agent successfully processed 100% of official test cases across device rings, account takeovers, card testing, and travel anomalies in an average of 250 milliseconds per case.*
>
> *TigerGraph gives financial institutions what tabular models can't: multi-hop relationship visibility, explainable evidence, and auditable human control. Thank you!"*
