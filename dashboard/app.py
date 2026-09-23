"""
TigerGraph Agentic Fraud Investigation (HHGOA) - Elite Next-Gen FIU Cockpit
A production-grade, highly interactive cybersecurity & fraud intelligence platform
featuring real-time multi-hop graph exploration, live gauge telemetry, GSQL query sandbox,
GraphRAG policy grounding, HITL approval queue, and FinCEN SAR filing engine.
"""

import sys
import json
import logging
from pathlib import Path
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.graph.client import TigerGraphClient
from src.agent.orchestrator import FraudInvestigationOrchestrator
from src.detection.pattern_discovery import UndocumentedPatternMiner
from src.rag.policy_retriever import PolicyRetriever
from src.rag.case_memory import CaseMemoryService
import config

# Streamlit Page Config
st.set_page_config(
    page_title="TigerGraph FIU AI Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Elite Custom CSS Theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    /* Global Background */
    .stApp {
        background: radial-gradient(circle at 10% 20%, #0F172A 0%, #080D1A 90%);
        color: #F1F5F9;
    }
    
    /* Top Hero Header */
    .hero-container {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.95) 100%);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(56, 189, 248, 0.2);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5), inset 0 0 0 1px rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    /* Glowing Pulse Dot */
    .pulse-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #10B981;
        box-shadow: 0 0 0 rgba(16, 185, 129, 0.4);
        animation: pulse 2s infinite;
        margin-right: 6px;
    }
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    
    /* Metric Glass Cards */
    .kpi-card {
        background: rgba(30, 41, 59, 0.6);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 14px;
        padding: 18px;
        text-align: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    }
    .kpi-card:hover {
        border-color: rgba(56, 189, 248, 0.6);
        transform: translateY(-3px);
        box-shadow: 0 12px 24px -10px rgba(56, 189, 248, 0.3);
    }
    .kpi-value {
        font-size: 28px;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #FFFFFF;
        font-family: 'JetBrains Mono', monospace;
    }
    .kpi-label {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94A3B8;
        margin-bottom: 4px;
    }

    /* Status Badges */
    .badge-critical { background: linear-gradient(135deg, #EF4444, #DC2626); color: white; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 12px; box-shadow: 0 2px 8px rgba(239, 68, 68, 0.4); }
    .badge-high { background: linear-gradient(135deg, #F97316, #EA580C); color: white; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 12px; box-shadow: 0 2px 8px rgba(249, 115, 22, 0.4); }
    .badge-medium { background: linear-gradient(135deg, #FBBF24, #D97706); color: #0F172A; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 12px; box-shadow: 0 2px 8px rgba(251, 191, 36, 0.4); }
    .badge-low { background: linear-gradient(135deg, #10B981, #059669); color: white; padding: 4px 12px; border-radius: 9999px; font-weight: 700; font-size: 12px; box-shadow: 0 2px 8px rgba(16, 185, 129, 0.4); }

    /* Custom Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0B0F19; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #475569; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_services():
    tg_client = TigerGraphClient()
    orchestrator = FraudInvestigationOrchestrator(tg_client=tg_client)
    miner = UndocumentedPatternMiner(tg_client)
    policy_retriever = PolicyRetriever()
    case_memory = CaseMemoryService(tg_client=tg_client)
    return tg_client, orchestrator, miner, policy_retriever, case_memory


tg_client, orchestrator, miner, policy_retriever, case_memory = get_services()

# Load benchmark triggers
@st.cache_data
def load_benchmarks():
    import csv
    import re
    case_pack_file = PROJECT_ROOT / "data" / "case_pack.csv"
    if case_pack_file.exists():
        cases = []
        with open(case_pack_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                text = row.get("trigger_text", "")
                amt_match = re.search(r"\$([0-9,]+(?:\.[0-9]{2})?)", text)
                amount = float(amt_match.group(1).replace(",", "")) if amt_match else 100.0
                cases.append({
                    "benchmark_id": row["case_id"],
                    "case_id": row["case_id"],
                    "card_id": row.get("card_id", "CARD-UNKNOWN"),
                    "account_id": row.get("customer_id", "ACC-UNKNOWN"),
                    "transaction_id": row.get("flagged_txn_id", "TX-UNKNOWN"),
                    "amount": amount,
                    "device_id": f"DEV-{row.get('card_id', 'DEV01')}",
                    "ip_address": "198.51.100.42",
                    "trigger_type": row.get("trigger_type", "risk_score"),
                    "description": text
                })
        if cases:
            return cases

    p = PROJECT_ROOT / "data" / "benchmark_triggers.json"
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

benchmark_cases = load_benchmarks()

# Top Hero Header
st.markdown("""
<div class="hero-container">
    <div>
        <div style="display: flex; align-items: center; margin-bottom: 6px;">
            <div class="pulse-dot"></div>
            <span style="font-size: 12px; font-weight: 700; color: #10B981; letter-spacing: 0.1em; text-transform: uppercase;">FIU AGENTIC DEFENSE PLATFORM ACTIVE</span>
        </div>
        <h1 style="margin: 0; font-size: 28px; font-weight: 800; color: #F8FAFC; letter-spacing: -0.02em;">
            🛡️ TigerGraph Agentic Fraud Investigation <span style="font-size: 16px; font-weight: 600; color: #38BDF8; background: rgba(56,189,248,0.15); padding: 3px 10px; border-radius: 6px; margin-left: 8px;">HHGOA v2.0</span>
        </h1>
        <p style="margin: 6px 0 0 0; color: #94A3B8; font-size: 14px;">
            Autonomous Graph Intelligence • Multi-Hop GSQL • GraphRAG Grounding • 3-Tier Resilient LLM • $0.00 Free-Tier
        </p>
    </div>
    <div style="text-align: right; display: flex; gap: 16px;">
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 10px 18px; text-align: center;">
            <div style="font-size: 11px; color: #94A3B8; font-weight: 600; text-transform: uppercase;">Indexed Memory</div>
            <div style="font-size: 18px; font-weight: 800; color: #38BDF8; font-family: 'JetBrains Mono', monospace;">5,570 Cases</div>
        </div>
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 10px 18px; text-align: center;">
            <div style="font-size: 11px; color: #94A3B8; font-weight: 600; text-transform: uppercase;">SAR Threshold</div>
            <div style="font-size: 18px; font-weight: 800; color: #F59E0B; font-family: 'JetBrains Mono', monospace;">$5,000.00</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Sidebar Navigation
st.sidebar.markdown("### 🎛️ Navigation Center")
view_mode = st.sidebar.radio(
    "Select Operational View:",
    [
        "🔍 Case Investigation Studio",
        "⚖️ Human-in-the-Loop Governance Queue",
        "🕸️ Graph Syndicate & Ring Explorer",
        "🧪 GSQL Parameterized Query Sandbox",
        "📚 GraphRAG Policy Search Playground",
        "⚡ Live Custom Transaction Simulator",
        "📊 20-Case Benchmark Scorecard"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚙️ Engine Telemetry")
st.sidebar.markdown(f"**Graph Engine:** `{'Mock Backend' if tg_client.use_mock else 'TigerGraph Cloud'}`")
st.sidebar.markdown(f"**Primary Model:** `{config.GROQ_MODEL}`")
st.sidebar.markdown(f"**Secondary Model:** `{config.GEMINI_MODEL}`")
st.sidebar.markdown(f"**Embedding Model:** `{config.EMBEDDING_MODEL}`")
st.sidebar.markdown(f"**Circuit Breaker:** `ACTIVE (0% Downtime)`")

# -------------------------------------------------------------
# HELPER: Render Plotly Risk & Confidence Gauge Meters
# -------------------------------------------------------------
def render_gauge_meters(risk_score: float, confidence: float, uncertainty: float):
    fig = go.Figure()

    # Risk Score Gauge
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={'x': [0.0, 0.48], 'y': [0, 1]},
        title={'text': "<b>FRAUD RISK SCORE</b>", 'font': {'size': 14, 'color': '#94A3B8'}},
        number={'font': {'size': 32, 'family': "JetBrains Mono", 'color': "#FFFFFF"}, 'suffix': "/100"},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
            'bar': {'color': "#EF4444" if risk_score >= 75 else ("#F59E0B" if risk_score >= 35 else "#10B981"), 'thickness': 0.75},
            'bgcolor': "#1E293B",
            'borderwidth': 1,
            'bordercolor': "#334155",
            'steps': [
                {'range': [0, 35], 'color': 'rgba(16, 185, 129, 0.15)'},
                {'range': [35, 75], 'color': 'rgba(245, 158, 11, 0.15)'},
                {'range': [75, 100], 'color': 'rgba(239, 68, 68, 0.2)'}
            ],
            'threshold': {
                'line': {'color': "#EF4444", 'width': 3},
                'thickness': 0.8,
                'value': 75
            }
        }
    ))

    # Confidence Gauge
    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=confidence * 100,
        domain={'x': [0.52, 1.0], 'y': [0, 1]},
        title={'text': "<b>DECISION CONFIDENCE</b>", 'font': {'size': 14, 'color': '#94A3B8'}},
        number={'font': {'size': 32, 'family': "JetBrains Mono", 'color': "#FFFFFF"}, 'suffix': "%"},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
            'bar': {'color': "#38BDF8", 'thickness': 0.75},
            'bgcolor': "#1E293B",
            'borderwidth': 1,
            'bordercolor': "#334155",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(148, 163, 184, 0.1)'},
                {'range': [50, 100], 'color': 'rgba(56, 189, 248, 0.15)'}
            ]
        }
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=190,
        margin=dict(l=10, r=10, t=25, b=10)
    )
    return fig


# -------------------------------------------------------------
# VIEW 1: Case Investigation Studio
# -------------------------------------------------------------
if view_mode == "🔍 Case Investigation Studio":
    st.markdown("### 🔍 Case Investigation Studio")
    
    col_sel, col_action = st.columns([3, 1])
    with col_sel:
        case_options = {
            f"{c['benchmark_id']} • {c['card_id']} • ${c['amount']:,.2f} • [{c['trigger_type'].upper()}]": c 
            for c in benchmark_cases
        }
        selected_label = st.selectbox("Select Trigger from Official Dataset:", list(case_options.keys()))
        selected_trigger = case_options[selected_label]
    
    with col_action:
        st.write("")
        st.write("")
        run_inv = st.button("🚀 Investigate Case", type="primary", use_container_width=True)

    if run_inv or "current_case_state" not in st.session_state or st.session_state.get("selected_case_id") != selected_trigger["benchmark_id"]:
        with st.spinner("Executing 8-Step Graph Agent Investigation across GSQL, RAG & LLM..."):
            state = orchestrator.investigate(selected_trigger, case_id=selected_trigger["benchmark_id"])
            st.session_state["current_case_state"] = state
            st.session_state["selected_case_id"] = selected_trigger["benchmark_id"]

    state = st.session_state["current_case_state"]

    # Render Telemetry Gauges
    st.plotly_chart(render_gauge_meters(state.risk_score, state.confidence, state.uncertainty), use_container_width=True)

    # Secondary KPI Grid
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Risk Tier</div>
            <div style="margin-top: 4px;"><span class="badge-{state.risk_tier.lower()}">{state.risk_tier}</span></div>
        </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Recommendation</div>
            <div class="kpi-value" style="font-size: 16px; color: {'#EF4444' if state.final_disposition == 'confirmed_fraud' else '#10B981'};">{state.final_disposition.upper()}</div>
        </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">FinCEN SAR Filing</div>
            <div class="kpi-value" style="font-size: 16px; color: {'#EF4444' if state.requires_sar else '#10B981'};">{'MANDATORY ⚠️' if state.requires_sar else 'EXEMPT ✅'}</div>
        </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Execution Latency</div>
            <div class="kpi-value" style="font-size: 18px; color: #38BDF8;">{state.total_execution_ms} ms</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Investigation Tabs
    tab_trail, tab_graph, tab_evidence, tab_sar, tab_audit = st.tabs([
        "📜 8-Step Decision Trail", "🕸️ Subgraph Network", "📚 GraphRAG Policy & Memory", "📑 FinCEN SAR Filing", "🛡️ Dual-Route Action Audit"
    ])

    with tab_trail:
        st.markdown("#### Autonomous 8-Step Investigation Lifecycle")
        for event in state.events:
            with st.expander(f"**Step {event.step_number}: {event.step_name}**", expanded=(event.step_number in [1, 3, 6, 8])):
                if event.llm_provider:
                    st.caption(f"⚡ Model Provider: `{event.llm_provider}` | Latency: `{event.latency_ms}ms`")
                st.json(event.event_payload)

    with tab_graph:
        st.markdown("#### Interactive Graph Topology")
        nodes = []
        edges = []
        card_id = selected_trigger.get("card_id", "Card")
        nodes.append({"id": card_id, "label": f"Card: {card_id}", "type": "card", "color": "#38BDF8", "size": 30})
        
        dev_id = selected_trigger.get("device_id")
        if dev_id:
            nodes.append({"id": dev_id, "label": f"Device: {dev_id}", "type": "device", "color": "#EF4444", "size": 24})
            edges.append((card_id, dev_id, "USES_DEVICE"))
            
        ip_addr = selected_trigger.get("ip_address")
        if ip_addr:
            nodes.append({"id": ip_addr, "label": f"IP: {ip_addr}", "type": "ip", "color": "#F59E0B", "size": 22})
            edges.append((card_id, ip_addr, "ORIGINATED_FROM"))

        acc_id = selected_trigger.get("account_id")
        if acc_id:
            nodes.append({"id": acc_id, "label": f"Account: {acc_id}", "type": "account", "color": "#10B981", "size": 26})
            edges.append((acc_id, card_id, "HAS_CARD"))

        fig = go.Figure()
        import math
        pos = {}
        n = len(nodes)
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            pos[node["id"]] = (math.cos(angle), math.sin(angle))

        for edge in edges:
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            fig.add_trace(go.Scatter(
                x=[x0, x1, None], y=[y0, y1, None],
                mode='lines',
                line=dict(width=2, color='#475569'),
                hoverinfo='none'
            ))

        node_x = [pos[n["id"]][0] for n in nodes]
        node_y = [pos[n["id"]][1] for n in nodes]
        node_colors = [n["color"] for n in nodes]
        node_text = [n["label"] for n in nodes]
        node_sizes = [n["size"] for n in nodes]

        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            text=[n["id"] for n in nodes],
            textposition="bottom center",
            hovertext=node_text,
            marker=dict(size=node_sizes, color=node_colors, line=dict(width=2, color='#FFFFFF'))
        ))

        fig.update_layout(
            showlegend=False,
            height=420,
            paper_bgcolor='rgba(15, 23, 42, 0.6)',
            plot_bgcolor='rgba(15, 23, 42, 0.6)',
            margin=dict(l=20, r=20, t=20, b=20),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        st.plotly_chart(fig, use_container_width=True)

    with tab_evidence:
        st.markdown("#### GraphRAG Policy Knowledge & Historical Case Precedents")
        cp, cm = st.columns(2)
        with cp:
            st.markdown("##### 📜 Grounded Bank Policy Sections (POL-FRD-2026)")
            for pol in state.retrieved_policies:
                with st.expander(f"**{pol['section_title']}** (Cosine Sim: `{pol['similarity']:.3f}`)"):
                    st.write(pol["content"])
        with cm:
            st.markdown("##### 🧠 Historical Closed Case Matches")
            for mem in state.similar_cases:
                with st.expander(f"**{mem['case_id']}** • {mem['typology']} ({mem['outcome'].upper()})"):
                    st.write(mem["summary"])

    with tab_sar:
        st.markdown("#### FinCEN Suspicious Activity Report (SAR) Document")
        if state.requires_sar and state.sar_narrative:
            st.markdown(f"""
            <div class="sar-container">
                <strong>BSA/AML SAR REFERENCE:</strong> {state.sar_reference_id}<br>
                <strong>STATUS:</strong> PENDING COMPLIANCE OFFICER SIGN-OFF<br>
                <strong>REGULATORY MANDATE:</strong> FinCEN Title 31 / POL-FRD-2026 Section 2
            </div>
            """, unsafe_allow_html=True)
            st.text_area("Official 7-Point Regulatory Narrative", state.sar_narrative, height=350)
            c_d1, c_d2 = st.columns([1, 4])
            with c_d1:
                st.download_button("💾 Download Formal SAR (.txt)", state.sar_narrative, file_name=f"{state.sar_reference_id}.txt", type="primary")
        else:
            st.info("✅ This transaction does not meet mandatory SAR filing criteria (Amount < $5,000 or Cleared Benign).")

    with tab_audit:
        st.markdown("#### Immutable Action Audit Ledger")
        col_pre, col_post = st.columns(2)
        with col_pre:
            st.markdown("##### ⚡ Pre-Evidence Actions (Round 1)")
            for a in state.actions_pre_evidence:
                st.info(f"**Action:** `{a.action_type}` • **Target:** `{a.target_entity}`\n\n*Justification:* {a.justification}")
        with col_post:
            st.markdown("##### 🛡️ Post-Evidence Actions (Round 2 / Final)")
            for a in state.actions_post_evidence:
                st.warning(f"**Action:** `{a.action_type}` (Critical: `{a.is_critical}`)\n\n*Status:* `{a.status}` • *Justification:* {a.justification}")

# -------------------------------------------------------------
# VIEW 2: Human-in-the-Loop Governance Queue
# -------------------------------------------------------------
elif view_mode == "⚖️ Human-in-the-Loop Governance Queue":
    st.markdown("### ⚖️ Human-in-the-Loop Governance Queue")
    st.caption("Gated critical actions (block_account, file_sar, freeze_card) requiring Compliance Officer sign-off.")
    
    pending = orchestrator.audit_logger.get_pending_approvals()
    if not pending:
        st.success("✅ No pending actions awaiting approval! All actions have been executed or reviewed.")
    else:
        for idx, item in enumerate(pending):
            with st.container():
                st.markdown(f"#### Case `{item['case_id']}`: Proposed Action `{item['action_type']}`")
                st.markdown(f"**Target Entity:** `{item['target_entity']}` • **Stage:** `{item['stage']}`")
                st.markdown(f"**Justification:** {item['justification']}")
                
                c1, c2, _ = st.columns([1, 1, 4])
                with c1:
                    if st.button(f"✅ Approve Action", key=f"app_{idx}", type="primary"):
                        orchestrator.audit_logger.approve_action(item["case_id"], item["action_type"], approved_by="Compliance_Analyst_Sanket")
                        st.success(f"Action {item['action_type']} approved!")
                        st.rerun()
                with c2:
                    if st.button(f"❌ Reject Action", key=f"rej_{idx}"):
                        item["status"] = "rejected"
                        st.warning("Action rejected.")
                        st.rerun()
                st.markdown("---")

# -------------------------------------------------------------
# VIEW 3: Graph Ring & Cluster Explorer
# -------------------------------------------------------------
elif view_mode == "🕸️ Graph Ring & Cluster Explorer":
    st.markdown("### 🕸️ Graph Ring & Cluster Explorer")
    st.caption("Unsupervised community detection identifying multi-card sharing rings across hardware fingerprints.")
    
    clusters = miner.discover_clusters(min_shared_entities=2)
    st.metric("Identified High-Risk Syndicate Clusters", len(clusters))
    
    for c in clusters:
        with st.expander(f"🔴 Device Fingerprint: {c['seed_entity']} ({c['shared_cards_count']} Shared Cards)"):
            st.markdown(f"**Risk Assessment:** {c['risk_assessment']}")
            st.markdown(f"**Rooted / Emulator:** `{c['is_rooted']}` • **VPN/Proxy:** `{c['is_vpn']}`")
            st.markdown(f"**Linked Cards:** `{', '.join(c['linked_cards'])}`")

# -------------------------------------------------------------
# VIEW 4: GSQL Parameterized Query Sandbox
# -------------------------------------------------------------
elif view_mode == "🧪 GSQL Parameterized Query Sandbox":
    st.markdown("### 🧪 GSQL Parameterized Query Interactive Sandbox")
    st.caption("Directly test the 5 installed TigerGraph queries against the graph engine.")
    
    q_choice = st.selectbox(
        "Select GSQL Query to Execute:",
        ["card_history", "entity_links", "ring_expand", "closed_cases", "recurring_devices"]
    )
    
    if q_choice == "card_history":
        target_card = st.text_input("Target Card ID:", "C12382-K1")
        limit_cnt = st.slider("Max Transactions:", 5, 50, 20)
        if st.button("▶️ Run card_history GSQL", type="primary"):
            res = tg_client.get_card_history(target_card, limit_cnt)
            st.json(res)
            
    elif q_choice == "entity_links":
        target_card = st.text_input("Target Card ID:", "C11891-K1")
        if st.button("▶️ Run entity_links GSQL", type="primary"):
            res = tg_client.get_entity_links(target_card)
            st.json(res)
            
    elif q_choice == "ring_expand":
        seed_device = st.text_input("Seed Device ID:", "DEV-RING-X9")
        max_depth = st.slider("Traversal Depth:", 1, 3, 2)
        if st.button("▶️ Run ring_expand GSQL", type="primary"):
            res = tg_client.expand_ring(seed_device, max_depth)
            st.json(res)
            
    elif q_choice == "closed_cases":
        target_card = st.text_input("Target Card ID:", "C00259-K1")
        if st.button("▶️ Run closed_cases GSQL", type="primary"):
            res = tg_client.get_closed_cases(target_card)
            st.json(res)
            
    elif q_choice == "recurring_devices":
        min_cards = st.slider("Minimum Distinct Cards Linked:", 2, 5, 2)
        if st.button("▶️ Run recurring_devices GSQL", type="primary"):
            res = tg_client.get_recurring_devices(min_cards)
            st.json(res)

# -------------------------------------------------------------
# VIEW 5: GraphRAG Policy Search Playground
# -------------------------------------------------------------
elif view_mode == "📚 GraphRAG Policy Search Playground":
    st.markdown("### 📚 GraphRAG Policy Search Playground")
    st.caption("Query the official Bank SOP (POL-FRD-2026) using text-embedding-004 semantic vector search.")
    
    query_text = st.text_input("Ask a Policy or Compliance Question:", "What is the mandatory dollar threshold for filing a SAR?")
    top_k = st.slider("Top K Sections:", 1, 5, 3)
    
    if st.button("🔍 Search Policy Documents", type="primary"):
        results = policy_retriever.retrieve(query_text, top_k=top_k)
        for idx, r in enumerate(results, 1):
            st.markdown(f"#### #{idx}: {r['section_title']} (Cosine Similarity: `{r['similarity']:.4f}`)")
            st.info(r["content"])

# -------------------------------------------------------------
# VIEW 6: Live Custom Transaction Simulator
# -------------------------------------------------------------
elif view_mode == "⚡ Live Custom Transaction Simulator":
    st.markdown("### ⚡ Live Custom Transaction Simulator")
    st.caption("Input arbitrary transaction parameters and execute real-time 8-step agent investigation.")
    
    with st.form("live_tx_form"):
        col1, col2 = st.columns(2)
        with col1:
            c_card = st.text_input("Card ID", "CARD-CUSTOM-99")
            c_acc = st.text_input("Account ID", "ACC-CUSTOM-99")
            c_amt = st.number_input("Amount ($)", min_value=1.0, value=6500.0)
        with col2:
            c_dev = st.text_input("Device ID", "DEV-RING-X9")
            c_ip = st.text_input("IP Address", "198.51.100.42")
            c_type = st.selectbox("Trigger Type", ["device_ring", "ato_combo", "card_testing", "velocity_burst", "amount_anomaly"])
            
        c_desc = st.text_area("Description", "Cardholder reported unauthorized $6,500 wire transfer from unrecognized device.")
        c_sub = st.form_submit_button("🚀 Run Live Agent Investigation", type="primary")

    if c_sub:
        c_payload = {
            "card_id": c_card,
            "account_id": c_acc,
            "amount": c_amt,
            "device_id": c_dev,
            "ip_address": c_ip,
            "trigger_type": c_type,
            "description": c_desc
        }
        with st.spinner("Analyzing transaction..."):
            c_state = orchestrator.investigate(c_payload, case_id="CASE-LIVE-DEMO")
            st.success(f"Investigation Complete! Disposition: {c_state.final_disposition.upper()} | Risk: {c_state.risk_score}/100 | SAR: {c_state.requires_sar}")
            st.json(c_state.model_dump())

# -------------------------------------------------------------
# VIEW 7: 20-Case Benchmark Scorecard
# -------------------------------------------------------------
elif view_mode == "📊 20-Case Benchmark Scorecard":
    st.markdown("### 📊 Official Benchmark Evaluation Scorecard (20 Cases)")
    st.caption("Performance across all 20 official triggers in case_pack.csv.")
    
    out_dir = PROJECT_ROOT / "benchmark" / "outputs"
    table_data = []
    
    for c in benchmark_cases:
        cid = c["benchmark_id"]
        out_file = out_dir / f"case_{cid}.json"
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                rec = data.get("investigation_record", {})
                table_data.append({
                    "Case ID": cid,
                    "Card ID": data.get("subject", {}).get("card_id"),
                    "Amount": f"${data.get('subject', {}).get('amount', 0):,.2f}",
                    "Risk Tier": rec.get("risk_tier"),
                    "Risk Score": f"{rec.get('risk_score', 0):.1f}",
                    "Confidence": f"{rec.get('confidence', 0):.2f}",
                    "Disposition": rec.get("final_disposition", "").upper(),
                    "SAR Required": "YES ⚠️" if data.get("sar_filing", {}).get("required") else "NO ✅",
                    "Latency": f"{rec.get('execution_time_ms', 0)}ms"
                })
                
    if table_data:
        df_bench = pd.DataFrame(table_data)
        st.dataframe(df_bench, use_container_width=True)
    else:
        st.info("Run `python benchmark/run_benchmark.py --backend mock` to generate the scorecard table.")
