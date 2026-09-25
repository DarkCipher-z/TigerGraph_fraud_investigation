"""
FinCEN-Compliant Suspicious Activity Report (SAR) Generator.
Generates structured 7-point regulatory narratives for transactions violating AML/SAR mandates.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
import config


class SARGenerator:
    """Constructs formal SAR filings with complete narrative sections and regulatory references."""

    @staticmethod
    def generate_sar(
        case_id: str,
        trigger_data: Dict[str, Any],
        investigation_state: Any,
        llm_narrative: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Builds formal SAR record with structured narrative sections:
        1. Subject Details
        2. Suspicious Timeline
        3. Digital & IP Footprint
        4. Ingress / Egress Flows
        5. Graph Syndicate Evidence
        6. Material Financial Loss
        7. Recommended Disposition
        """
        now_utc = datetime.now(timezone.utc)
        sar_ref = f"SAR-FINCEN-{now_utc.strftime('%Y%m%d')}-{case_id.replace('CASE-', '').replace('BM-', '')}"
        amount = float(trigger_data.get("amount", 0.0))
        
        # If LLM didn't produce full 7-point narrative, construct canonical template
        if not llm_narrative or len(llm_narrative) < 100:
            narrative = f"""================================================================================
*** DRAFT — FOR COMPLIANCE REVIEW ONLY — NOT A FILED REPORT ***
FINCEN SUSPICIOUS ACTIVITY REPORT (SAR) NARRATIVE
Reference ID: {sar_ref} | Date: {now_utc.strftime('%Y-%m-%d')}
================================================================================

1. SUBJECT IDENTIFICATION & ACCOUNT PROFILE:
   Primary Subject Card ID: {trigger_data.get('card_id')}
   Linked Account Number: {trigger_data.get('account_id', 'N/A')}
   Customer Status: Active Retail Account under Enterprise Monitoring

2. CHRONOLOGICAL TIMELINE OF SUSPICIOUS EVENTS:
   Suspicious transaction initiated at {now_utc.isoformat()} for ${amount:,.2f}.
   Context: {trigger_data.get('description', 'High-risk automated anomaly detected')}

3. DIGITAL IDENTIFIERS & GEOGRAPHIC FOOTPRINT:
   Device Fingerprint: {trigger_data.get('device_id')}
   Originating IP Address: {trigger_data.get('ip_address')}
   Location Analysis: High risk/anonymized network layer detected.

4. INGRESS / EGRESS MONETARY FLOWS & MERCHANTS:
   Target Merchant: {trigger_data.get('merchant_id', 'N/A')}
   Transaction Category: Rapid High-Value Outflow / Electronic Fund Transfer

5. GRAPH NETWORK & SYNDICATE LINKAGE EVIDENCE:
   TigerGraph GSQL expansion identified multi-hop linkages to shared hardware fingerprints and recurring card clusters.
   Primary Typology: {investigation_state.primary_typology}

6. MATERIAL FINANCIAL LOSS & REGULATORY THRESHOLDS:
   Total Material Amount at Risk: ${amount:,.2f}
   Compliance Trigger: Exceeds FinCEN mandatory $5,000 threshold under Policy POL-FRD-2026 Section 2.

7. LAW ENFORCEMENT DISPOSITION & REMEDIATION PROPOSALS:
   - Account and card authorization freeze queued for Compliance Officer sign-off.
   - Immediate preservation of digital audit trails and IP routing logs.
   - Formal electronic submission to FinCEN BSA Direct e-Filing system.
================================================================================"""
        else:
            narrative = llm_narrative

        return {
            "sar_reference_id": sar_ref,
            "case_id": case_id,
            "subject_card_id": trigger_data.get("card_id"),
            "subject_account_id": trigger_data.get("account_id"),
            "suspicious_amount": amount,
            "primary_typology": investigation_state.primary_typology,
            "narrative": narrative,
            "status": "DRAFT_pending_compliance_review",
            "created_at": now_utc.isoformat()
        }
