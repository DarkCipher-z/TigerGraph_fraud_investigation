# 🎬 Demo Video Script (3–5 Minutes)
**Project:** TigerGraph Agentic Fraud Investigation (HHGOA)  
**Target Duration:** ~3:30 to 4:30 Minutes  

---

## ⏱️ Video Breakdown Summary
- **0:00 – 0:40**: Problem Hook & High-Level Architecture ($0.00 Free Tier)
- **0:40 – 1:30**: Deep Dive into Case 1 (Syndicated Device Ring & 8-Step Investigation)
- **1:30 – 2:30**: GraphRAG Policy Grounding & Historical Memory Precedents
- **2:30 – 3:20**: Human-in-the-Loop Approval Queue & FinCEN SAR Filing
- **3:20 – 4:00**: Real-Time Custom Trigger & Benchmark Suite
- **4:00 – 4:30**: Conclusion & Future Roadmap

---

## 📝 Scene-by-Scene Script

---

### **Scene 1: Introduction & The Fraud Problem (0:00 – 0:40)**

**Visuals On Screen:**
- Start on the **Streamlit Dashboard** homepage (`python -m streamlit run dashboard/app.py`).
- Show the top navigation bar and system status indicators (**TigerGraph Backend, Groq Llama 3.3 70B, Google Gemini Flash**).

**Voiceover / Script:**
> *"Hi everyone! Welcome to our demo of the **TigerGraph Agentic Fraud Investigation System**—an autonomous, graph-native Financial Intelligence Unit copilot built entirely on a **zero-cost, $0.00 free-tier architecture**.*
>
> *Traditional tabular fraud models fail because they evaluate transactions in isolation. Modern financial crime is syndicated: fraudsters use rooted emulators, distributed device rings, and automated bot scripts across dozens of stolen cards.*
>
> *Our solution combines **TigerGraph's multi-hop GSQL graph traversals**, **GraphRAG policy grounding**, **historical case memory**, and an **8-step autonomous agent loop** to investigate and resolve fraud in real time."*

---

### **Scene 2: Case Investigation & 8-Step Decision Trail (0:40 – 1:30)**

**Visuals On Screen:**
- In the **Case Investigation Explorer**, select **BM-001 - CARD-2001 ($2,850.00) [device_ring]**.
- Click the blue **"🚀 Run 8-Step Agent Investigation"** button.
- Show the Top Metric Banner update: **Risk Score: 99.0/100 (CRITICAL)**, **Confidence: 77.0%**, **Disposition: CONFIRMED_FRAUD**, **SAR Required: YES ⚠️**.
- Switch to the **"📜 8-Step Decision Trail"** tab and expand steps 1, 2, 3, and 6.

**Voiceover / Script:**
> *"Let's investigate benchmark case **BM-001**—a suspicious \$2,850 transaction originating from device `DEV-RING-X9`.*
>
> *When we click investigate, our 8-step agent immediately kicks off:*
> - *In **Step 2**, it queries TigerGraph using GSQL `ring_expand` and `entity_links`, traversing multi-hop edges to discover that this single hardware fingerprint is actively shared across 3 distinct cards.*
> - *In **Step 3**, our heuristic detector fires the `SIG-RING-02` signal with high severity.*
> - *In **Step 6**, the mathematical risk engine computes a risk score of 99.0, placing this case in the CRITICAL tier and proposing immediate pre-evidence mitigation."*

---

### **Scene 3: Graph Neighborhood & GraphRAG Grounding (1:30 – 2:30)**

**Visuals On Screen:**
- Click on the **"🕸️ Graph Neighborhood"** tab. Show the interactive Plotly network diagram linking the Card, Device, IP, and Account.
- Click on the **"📚 Policy & Memory Evidence"** tab. Expand the retrieved policy chunk (**Typology B: Distributed Device Ring**) and historical memory match (**CASE-HIST-001**).

**Voiceover / Script:**
> *"Under the **Graph Neighborhood** tab, we can visually inspect the entity graph linking this card to the device ring and IP routing footprint.*
>
> *Crucially, our agent doesn't guess or hallucinate—it uses **GraphRAG policy grounding**.*
> *Under the **Policy & Memory Evidence** tab, you can see how it semantically retrieved the exact bank SOP clause from `POL-FRD-2026` regarding multi-device rings, along with historical closed case `CASE-HIST-001`, which previously confirmed fraud on this exact device ring. This precedent dynamically adjusted our agent's confidence and risk assessment."*

---

### **Scene 4: Human-in-the-Loop Approval & FinCEN SAR Filing (2:30 – 3:20)**

**Visuals On Screen:**
- Click on the **"📑 Action Audit & SAR"** tab. Scroll down to display the generated **FinCEN 7-Point SAR Narrative**.
- In the sidebar navigation, click on **"Human Approval Queue"**.
- Point out the queued `freeze_card` and `file_sar` critical actions.
- Click **"✅ Approve Action"** and show the instant status update.

**Voiceover / Script:**
> *"Now let's look at governance. Under **Action Audit & SAR**, notice how our agent separated non-critical actions from critical actions.*
>
> *Because high-impact punitive actions like `freeze_card` and `file_sar` can severely impact customers, our policy strictly forbids auto-execution. Instead, they are routed to the **Human Approval Queue**.*
>
> *As a Compliance Officer, I can review the rationale and approve the action with a single click. Furthermore, because aggregate fraud exceeded the mandatory \$5,000 regulatory threshold, the agent synthesized a complete, FinCEN-compliant 7-point SAR narrative ready for filing."*

---

### **Scene 5: Real-Time Custom Trigger & Benchmark Scorecard (3:20 – 4:00)**

**Visuals On Screen:**
- In the sidebar, select **"Interactive Case Trigger"**.
- Enter a transaction amount of \$12,000, select `ato_combo`, and click **"🚀 Investigate Custom Transaction"**.
- Quickly show the terminal running `python benchmark/run_benchmark.py --backend mock`, displaying the clean 20/20 summary grid.

**Voiceover / Script:**
> *"Analysts can also test arbitrary transactions on the fly in our **Interactive Case Trigger** tab.*
>
> *In our automated evaluation, we ran all 20 official benchmark test cases across device rings, account takeovers, BIN attacks, and benign travel. Every case was successfully investigated, categorized, and written into schema-validated answer files in milliseconds."*

---

### **Scene 6: Conclusion (4:00 – 4:30)**

**Visuals On Screen:**
- Switch back to the Streamlit Dashboard or GitHub repository view.
- Show `README.md`, `ARCHITECTURE.md`, and test outputs.

**Voiceover / Script:**
> *"In summary, the TigerGraph Agentic Fraud Investigation system demonstrates how combining graph database traversals, GraphRAG semantic grounding, and resilient LLM orchestration creates an auditable, enterprise-ready defense against modern financial crime—all at zero infrastructure cost.*
>
> *Thank you for watching, and check out our GitHub repository and technical blog post for full code and documentation!"*

---

## 🎙️ Recording Tips for the Presenter:
1. **Resolution**: Record at 1080p (1920x1080) in full screen.
2. **Launch Command**: Start the dashboard before recording with:
   ```powershell
   python -m streamlit run dashboard/app.py
   ```
3. **Cursor Cues**: Move your mouse deliberately to highlight the tabs, risk score delta badges, and approval buttons as you speak.
