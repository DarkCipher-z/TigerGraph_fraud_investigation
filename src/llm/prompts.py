"""
Structured Prompt Templates for Fraud Investigation & SAR Synthesis.
"""

import json
from typing import Dict, Any, List


class PromptBuilder:
    """Constructs grounded prompts enforcing strict JSON output schemas."""

    @staticmethod
    def build_investigation_prompt(
        case_id: str,
        trigger_data: Dict[str, Any],
        graph_summary: Dict[str, Any],
        fired_signals: List[Dict[str, Any]],
        retrieved_policies: List[Dict[str, Any]],
        similar_cases: List[Dict[str, Any]],
        round_number: int = 1
    ) -> str:
        """Constructs system & context prompt for investigation reasoning."""
        
        prompt = f"""You are an elite Autonomous Fraud Investigation Agent operating within Horizon National Bank's Financial Intelligence Unit.
Investigate the transaction below using the provided Graph Neighborhood, Fired Signals, Bank Policies, and Historical Case Precedents.

### 1. Case Trigger
- Case ID: {case_id}
- Card ID: {trigger_data.get('card_id')}
- Account ID: {trigger_data.get('account_id')}
- Transaction Amount: ${float(trigger_data.get('amount', 0)):,.2f}
- Device ID: {trigger_data.get('device_id')}
- IP Address: {trigger_data.get('ip_address')}
- Trigger Description: {trigger_data.get('description')}
- Investigation Round: {round_number}

### 2. Graph Neighborhood Summary
- Multi-Hop Linked Cards: {graph_summary.get('linked_cards_count', 1)}
- Shared Devices Count: {graph_summary.get('shared_devices_count', 1)}
- Graph Neighbors: {json.dumps(graph_summary.get('neighbors', []), indent=2)}

### 3. Fired Heuristic Signals
{json.dumps(fired_signals, indent=2)}

### 4. Grounded Bank Policies (GraphRAG)
{json.dumps(retrieved_policies, indent=2)}

### 5. Historical Closed Case Memory Precedents
{json.dumps(similar_cases, indent=2)}

### Investigation Guidelines:
1. Ground your reasoning strictly in the provided policy rules (e.g. SAR thresholds >= $5,000, Multi-device ring rules, ATO procedures).
2. Distinguish between non-critical autonomous actions (e.g., `step_up_mfa`, `notify_customer`) and CRITICAL actions (e.g., `block_account`, `file_sar`, `freeze_card`).
3. Critical actions MUST be tagged `requires_human_approval: true`.
4. Provide a step-by-step reasoning trail.

Return ONLY a valid JSON object matching this exact schema:
{{
  "reasoning_summary": "Detailed 3-4 sentence explanation of the graph topology, fired signals, and risk basis.",
  "recommended_disposition": "confirmed_fraud" | "cleared_benign" | "escalate_to_analyst",
  "proposed_actions": [
    {{
      "action_type": "block_account" | "freeze_card" | "step_up_mfa" | "file_sar" | "notify_customer" | "allow_transaction",
      "target_entity": "string",
      "is_critical": boolean,
      "requires_human_approval": boolean,
      "justification": "string"
    }}
  ],
  "requires_sar_filing": boolean,
  "sar_rationale": "string or empty if no SAR needed"
}}
"""
        return prompt

    @staticmethod
    def build_sar_narrative_prompt(
        case_id: str,
        trigger_data: Dict[str, Any],
        investigation_result: Dict[str, Any],
        retrieved_policies: List[Dict[str, Any]]
    ) -> str:
        """Constructs prompt for FinCEN-compliant SAR narrative."""
        prompt = f"""You are a Bank Secrecy Act / Anti-Money Laundering (BSA/AML) Compliance Officer.
Draft a formal, structured 7-section Suspicious Activity Report (SAR) narrative for submission to FinCEN.

### Case Details:
- Case Reference ID: {case_id}
- Primary Subject / Card: {trigger_data.get('card_id')} (Account: {trigger_data.get('account_id')})
- Suspicious Transaction Amount: ${float(trigger_data.get('amount', 0)):,.2f}
- Digital Footprint: Device {trigger_data.get('device_id')}, IP {trigger_data.get('ip_address')}
- Primary Fraud Typology: {investigation_result.get('primary_typology', 'Fraudulent Activity')}
- Investigation Rationale: {investigation_result.get('reasoning_summary', '')}

### Required FinCEN SAR 7-Point Structure:
1. SUBJECT IDENTIFICATION & ACCOUNT PROFILE
2. CHRONOLOGICAL TIMELINE OF SUSPICIOUS EVENTS
3. DIGITAL IDENTIFIERS & GEOGRAPHIC FOOTPRINT
4. INGRESS / EGRESS MONETARY FLOWS & MERCHANTS
5. GRAPH NETWORK & SYNDICATE LINKAGE EVIDENCE
6. MATERIAL FINANCIAL LOSS & REGULATORY THRESHOLDS
7. LAW ENFORCEMENT DISPOSITION & REMEDIATION PROPOSALS

Generate the formal SAR text now.
"""
        return prompt
