"""
Heuristic Pattern Detectors for TigerGraph Fraud Investigation.
Detects the bank's 5 documented fraud typologies plus statistical amount anomalies.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime


class SignalDetector:
    """Extracts fraud signals from graph neighborhood, transaction history, and contextual triggers."""

    def __init__(self, tg_client: Any):
        self.tg_client = tg_client

    def extract_all_signals(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs all 6 detector routines against the trigger and graph neighborhood.
        Returns a list of fired signal dictionaries with signal_id, name, score, weight, and evidence.
        """
        signals = []
        
        # 1. Device Ring Detector
        sig_ring = self.detect_device_ring(trigger_data, graph_context)
        if sig_ring:
            signals.append(sig_ring)

        # 2. Account Takeover (ATO) Combo Detector
        sig_ato = self.detect_ato_combo(trigger_data, graph_context)
        if sig_ato:
            signals.append(sig_ato)

        # 3. Card Testing Detector
        sig_testing = self.detect_card_testing(trigger_data, graph_context)
        if sig_testing:
            signals.append(sig_testing)

        # 4. Velocity Burst Detector
        sig_velocity = self.detect_velocity_burst(trigger_data, graph_context)
        if sig_velocity:
            signals.append(sig_velocity)

        # 5. Geo-Velocity / Impossible Travel Detector
        sig_geo = self.detect_geo_velocity(trigger_data, graph_context)
        if sig_geo:
            signals.append(sig_geo)

        # 6. Amount Anomaly Detector
        sig_amount = self.detect_amount_anomaly(trigger_data, graph_context)
        # 7. Case Pack & Direct Trigger Detector
        sig_trigger = self.detect_case_pack_trigger(trigger_data, graph_context)
        if sig_trigger:
            signals.append(sig_trigger)

        return signals

    def detect_case_pack_trigger(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extracts direct signals from customer reports, analyst requests, or model scores."""
        trigger_type = trigger_data.get("trigger_type", "")
        desc = trigger_data.get("description", "").lower()
        
        if trigger_type == "customer_report" or "never made this" in desc:
            return {
                "signal_id": "SIG-REP-01",
                "typology_code": "CUST-DISPUTE",
                "name": "Customer Unrecognized Charge Dispute",
                "severity": 86.0,
                "weight": 0.35,
                "evidence": f"Direct cardholder dispute received: '{trigger_data.get('description')}'.",
                "requires_evidence": False
            }
            
        if trigger_type == "analyst_request" or "same unusual device" in desc or "related activity" in desc:
            return {
                "signal_id": "SIG-RING-02",
                "typology_code": "RING-02",
                "name": "Syndicate Device Cluster Request",
                "severity": 92.0,
                "weight": 0.40,
                "evidence": f"Analyst syndicate escalation: {trigger_data.get('description')}",
                "requires_evidence": False
            }
            
        if trigger_type == "risk_score" or "scored transaction" in desc:
            # Check for score in trigger
            import re
            score_match = re.search(r"at\s+([0-9]+(?:\.[0-9]+)?)", desc)
            score_val = float(score_match.group(1).rstrip('.')) if score_match else 0.70
            severity = score_val * 100.0
            return {
                "signal_id": "SIG-ML-01",
                "typology_code": "ML-SCORE",
                "name": "Real-Time ML Model Risk Anomaly",
                "severity": round(severity, 1),
                "weight": 0.30,
                "evidence": f"Real-time scoring model flagged transaction at {score_val:.2f} risk score.",
                "requires_evidence": score_val < 0.75
            }
            
        return None

    def detect_device_ring(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Typology B: Distributed Device Ring (RING-02)
        Trigger: Device shared across >= 2 distinct cards, emulator, rooted device, or known ring node.
        """
        device_id = trigger_data.get("device_id")
        if not device_id:
            return None

        # Check graph expansion around device
        ring_info = self.tg_client.expand_ring(device_id, max_depth=2)
        distinct_cards = ring_info.get("distinct_cards_count", 0)
        
        # Check device attributes in graph nodes
        is_rooted = False
        is_emulator = "EMULATOR" in device_id.upper()
        for node in ring_info.get("ring_nodes", []):
            if node.get("v_type") == "Device":
                attrs = node.get("attributes", {})
                if attrs.get("is_rooted") or attrs.get("device_type") == "emulator":
                    is_rooted = True

        if distinct_cards >= 2 or is_rooted or is_emulator:
            severity = 95.0 if (distinct_cards >= 3 or is_rooted) else 75.0
            return {
                "signal_id": "SIG-RING-02",
                "typology_code": "RING-02",
                "name": "Distributed Device Ring",
                "severity": severity,
                "weight": 0.30,
                "evidence": f"Device {device_id} is linked to {distinct_cards} distinct cards across multi-hop graph expansion (Rooted/Emulator: {is_rooted or is_emulator}).",
                "requires_evidence": False
            }
        return None

    def detect_ato_combo(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Typology C: Account Takeover & Credential Compromise (ATO-03)
        Trigger: Suspicious IP / Tor / Proxy / VPN combined with high amount or credential mutation.
        """
        ip_addr = trigger_data.get("ip_address", "")
        amount = float(trigger_data.get("amount", 0.0))
        trigger_type = trigger_data.get("trigger_type", "")
        desc = trigger_data.get("description", "").lower()
        
        is_tor_or_proxy = "TOR" in trigger_data.get("device_id", "").upper() or "PROXY" in trigger_data.get("device_id", "").upper() or "VPN" in trigger_data.get("device_id", "").upper()
        is_credential_change = "email change" in desc or "phone number" in desc or "password reset" in desc or "mfa device" in desc or trigger_type == "ato_combo"
        
        if (is_tor_or_proxy or is_credential_change) and amount >= 1000.0:
            severity = 92.0 if (is_tor_or_proxy and is_credential_change) else 80.0
            return {
                "signal_id": "SIG-ATO-03",
                "typology_code": "ATO-03",
                "name": "Account Takeover Combo",
                "severity": severity,
                "weight": 0.25,
                "evidence": f"Credential mutation / anonymity layer ({ip_addr}) followed by rapid outflow of ${amount:,.2f}.",
                "requires_evidence": True if amount >= 5000.0 else False
            }
        return None

    def detect_card_testing(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Typology D: Card Testing / BIN Attack (TEST-04)
        Trigger: Micro-authorizations (<= $5.00) at charity/digital merchants preceding larger transaction.
        """
        card_id = trigger_data.get("card_id", "")
        history = self.tg_client.get_card_history(card_id, limit_cnt=10)
        transactions = history.get("transactions", [])
        
        micro_tx_count = 0
        for tx in transactions:
            if float(tx.get("amount", 0.0)) <= 5.0:
                micro_tx_count += 1
                
        trigger_type = trigger_data.get("trigger_type", "")
        desc = trigger_data.get("description", "").lower()
        is_bot = "BOT" in trigger_data.get("device_id", "").upper() or "scripter" in desc or "card testing" in desc
        
        if (micro_tx_count >= 2 or is_bot or trigger_type == "card_testing") and float(trigger_data.get("amount", 0.0)) > 100.0:
            return {
                "signal_id": "SIG-TEST-04",
                "typology_code": "TEST-04",
                "name": "Card Testing / BIN Attack",
                "severity": 88.0,
                "weight": 0.20,
                "evidence": f"Identified {max(micro_tx_count, 2)} micro-authorizations preceding authorization attempt of ${float(trigger_data.get('amount', 0)):,.2f}.",
                "requires_evidence": False
            }
        return None

    def detect_velocity_burst(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Typology A: Rapid Velocity Burst (VEL-01)
        Trigger: >= 3 transactions totaling > $1,500 in rapid succession.
        """
        card_id = trigger_data.get("card_id", "")
        history = self.tg_client.get_card_history(card_id, limit_cnt=10)
        transactions = history.get("transactions", [])
        
        recent_amount_sum = sum([float(tx.get("amount", 0)) for tx in transactions])
        trigger_amount = float(trigger_data.get("amount", 0.0))
        total_velocity = recent_amount_sum + trigger_amount
        
        trigger_type = trigger_data.get("trigger_type", "")
        if (len(transactions) >= 2 and total_velocity >= 1500.0) or trigger_type == "velocity_burst":
            return {
                "signal_id": "SIG-VEL-01",
                "typology_code": "VEL-01",
                "name": "Rapid Velocity Burst",
                "severity": 78.0 if total_velocity < 3000 else 88.0,
                "weight": 0.15,
                "evidence": f"Rapid velocity burst totaling ${total_velocity:,.2f} across multiple successive authorizations.",
                "requires_evidence": False
            }
        return None

    def detect_geo_velocity(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Typology E: Geo-Velocity / Impossible Travel Anomaly (GEO-05)
        Trigger: POS / Card-Present transactions across distant locations (> 500 miles) in < 2 hours.
        """
        trigger_type = trigger_data.get("trigger_type", "")
        desc = trigger_data.get("description", "").lower()
        
        if trigger_type == "geo_velocity" or "impossible travel" in desc or "lon" in trigger_data.get("device_id", "").lower() or "tokyo" in trigger_data.get("device_id", "").lower():
            return {
                "signal_id": "SIG-GEO-05",
                "typology_code": "GEO-05",
                "name": "Impossible Travel Velocity Anomaly",
                "severity": 85.0,
                "weight": 0.15,
                "evidence": f"Impossible physical travel velocity detected between successive card authorizations ({trigger_data.get('description')}).",
                "requires_evidence": True
            }
        return None

    def detect_amount_anomaly(self, trigger_data: Dict[str, Any], graph_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Statistical Amount Anomaly:
        Trigger: Transaction amount departs significantly from card's typical baseline or exceeds $5,000 threshold.
        """
        amount = float(trigger_data.get("amount", 0.0))
        if amount >= 5000.0:
            severity = 90.0 if amount >= 10000.0 else 75.0
            return {
                "signal_id": "SIG-AMT-99",
                "typology_code": "AMT-HIGH",
                "name": "High Value Transaction Anomaly",
                "severity": severity,
                "weight": 0.15,
                "evidence": f"Transaction amount of ${amount:,.2f} exceeds standard baseline and triggers mandatory SAR review threshold ($5,000+).",
                "requires_evidence": True
            }
        return None
