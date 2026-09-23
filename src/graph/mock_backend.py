"""
In-memory Graph Backend for TigerGraph Agentic Fraud Investigation.
Simulates TigerGraph Graph Engine and GSQL installed query execution
for local testing, CI, and $0.00 free-tier evaluation without active cloud instances.
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class MockGraphBackend:
    """
    High-fidelity in-memory simulator of TigerGraph FraudGraph.
    Implements exact data structures and query behaviors for:
    - card_history
    - entity_links
    - ring_expand
    - closed_cases
    - recurring_devices
    """

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).resolve().parent.parent.parent / "data"
        self.data_dir = Path(data_dir)
        
        # Vertices stores
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.cards: Dict[str, Dict[str, Any]] = {}
        self.transactions: Dict[str, Dict[str, Any]] = {}
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.ips: Dict[str, Dict[str, Any]] = {}
        self.merchants: Dict[str, Dict[str, Any]] = {}
        self.fraud_cases: Dict[str, Dict[str, Any]] = {}
        self.policy_chunks: Dict[str, Dict[str, Any]] = {}
        
        # Adjacency mappings
        self.card_to_transactions: Dict[str, List[str]] = {}
        self.tx_to_device: Dict[str, str] = {}
        self.tx_to_ip: Dict[str, str] = {}
        self.tx_to_merchant: Dict[str, str] = {}
        self.card_to_account: Dict[str, str] = {}
        self.account_to_cards: Dict[str, List[str]] = {}
        self.card_to_devices: Dict[str, List[str]] = {}
        self.device_to_cards: Dict[str, List[str]] = {}
        self.card_to_ips: Dict[str, List[str]] = {}
        self.ip_to_cards: Dict[str, List[str]] = {}
        self.entity_to_cases: Dict[str, List[str]] = {}
        
        self.load_data()

    def load_data(self):
        """Populates graph from CSV transactions and closed cases JSON/CSV."""
        # 1. Load closed cases from CSV history if present
        history_csv = self.data_dir / "closed_cases_history.csv"
        if history_csv.exists():
            with open(history_csv, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    case_id = row["case_id"]
                    outcome = "confirmed_fraud" if "fraud" in row.get("outcome", "").lower() else "cleared_benign"
                    self.fraud_cases[case_id] = {
                        "case_id": case_id,
                        "status": "closed",
                        "outcome": outcome,
                        "risk_score": 90.0 if outcome == "confirmed_fraud" else 20.0,
                        "confidence": 0.92,
                        "typology": row.get("pattern", "Fraud Pattern"),
                        "investigator_notes": row.get("analyst_notes", ""),
                        "sar_filed": row.get("report_filed", "No").lower() == "yes",
                        "closed_at": row.get("closed_at", "")
                    }
                    if row.get("card_id"):
                        self.entity_to_cases.setdefault(row["card_id"], []).append(case_id)
                    if row.get("customer_id"):
                        self.entity_to_cases.setdefault(row["customer_id"], []).append(case_id)

        # Also load sample closed cases
        cases_file = self.data_dir / "sample_closed_cases.json"
        if cases_file.exists():
            with open(cases_file, "r", encoding="utf-8") as f:
                cases = json.load(f)
                for c in cases:
                    case_id = c["case_id"]
                    self.fraud_cases[case_id] = {
                        "case_id": case_id,
                        "status": "closed",
                        "outcome": c.get("outcome", "confirmed_fraud"),
                        "risk_score": c.get("risk_score", 90.0),
                        "confidence": c.get("confidence", 0.9),
                        "typology": c.get("typology", ""),
                        "investigator_notes": c.get("investigator_notes", ""),
                        "sar_filed": c.get("sar_filed", False),
                        "closed_at": c.get("closed_at", "")
                    }
                    if "primary_card_id" in c:
                        self.entity_to_cases.setdefault(c["primary_card_id"], []).append(case_id)
                    if "associated_device_id" in c:
                        self.entity_to_cases.setdefault(c["associated_device_id"], []).append(case_id)
                    if "primary_account_id" in c:
                        self.entity_to_cases.setdefault(c["primary_account_id"], []).append(case_id)

        # 2. Load transactions CSV
        tx_file = self.data_dir / "synthetic_transactions.csv"
        if tx_file.exists():
            with open(tx_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    tx_id = row["transaction_id"]
                    card_id = row["card_id"]
                    acc_id = row["account_id"]
                    dev_id = row["device_id"]
                    ip_addr = row["ip_address"]
                    merc_id = row["merchant_id"]
                    
                    # Store Transaction Vertex
                    self.transactions[tx_id] = {
                        "transaction_id": tx_id,
                        "amount": float(row["amount"]),
                        "timestamp": row["timestamp"],
                        "channel": row["channel"],
                        "is_declined": row.get("is_declined", "false").lower() == "true",
                        "declined_reason": row.get("declined_reason", "none")
                    }
                    
                    # Store Card Vertex
                    if card_id not in self.cards:
                        self.cards[card_id] = {
                            "card_id": card_id,
                            "status": "active",
                            "daily_limit": 5000.0
                        }
                        
                    # Store Account Vertex
                    if acc_id not in self.accounts:
                        self.accounts[acc_id] = {
                            "account_id": acc_id,
                            "status": "active",
                            "customer_risk_tier": "standard"
                        }
                        
                    # Store Device Vertex
                    if dev_id not in self.devices:
                        self.devices[dev_id] = {
                            "device_id": dev_id,
                            "device_type": row.get("device_type", "desktop"),
                            "is_rooted": row.get("is_rooted", "false").lower() == "true",
                            "is_vpn": row.get("is_vpn", "false").lower() == "true"
                        }
                        
                    # Store IP Vertex
                    if ip_addr not in self.ips:
                        self.ips[ip_addr] = {
                            "ip_address": ip_addr,
                            "country": row.get("ip_country", "US"),
                            "is_proxy": row.get("is_vpn", "false").lower() == "true"
                        }
                        
                    # Store Merchant Vertex
                    if merc_id not in self.merchants:
                        self.merchants[merc_id] = {
                            "merchant_id": merc_id,
                            "merchant_name": row.get("merchant_name", "Merchant"),
                            "mcc_code": row.get("mcc_code", "5411"),
                            "category": row.get("category", "General")
                        }
                        
                    # Build edges
                    self.card_to_transactions.setdefault(card_id, []).append(tx_id)
                    self.tx_to_device[tx_id] = dev_id
                    self.tx_to_ip[tx_id] = ip_addr
                    self.tx_to_merchant[tx_id] = merc_id
                    
                    self.card_to_account[card_id] = acc_id
                    self.account_to_cards.setdefault(acc_id, []).append(card_id)
                    
                    if dev_id not in self.card_to_devices.setdefault(card_id, []):
                        self.card_to_devices[card_id].append(dev_id)
                    if card_id not in self.device_to_cards.setdefault(dev_id, []):
                        self.device_to_cards[dev_id].append(card_id)
                        
                    if ip_addr not in self.card_to_ips.setdefault(card_id, []):
                        self.card_to_ips[card_id].append(ip_addr)
                    if card_id not in self.ip_to_cards.setdefault(ip_addr, []):
                        self.ip_to_cards[ip_addr].append(card_id)

    # -------------------------------------------------------------
    # GSQL Query Implementations
    # -------------------------------------------------------------

    def run_installed_query(self, query_name: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Dispatch helper matching TigerGraph REST response format."""
        if query_name == "card_history":
            return [self.card_history(params.get("target_card", ""), int(params.get("limit_cnt", 50)))]
        elif query_name == "entity_links":
            return [self.entity_links(params.get("target_card", ""))]
        elif query_name == "ring_expand":
            return [self.ring_expand(params.get("seed_device", ""), int(params.get("max_depth", 2)))]
        elif query_name == "closed_cases":
            return [self.closed_cases(params.get("target_card", ""))]
        elif query_name == "recurring_devices":
            return [self.recurring_devices(int(params.get("min_cards", 2)))]
        else:
            raise ValueError(f"Unknown query: {query_name}")

    def card_history(self, target_card: str, limit_cnt: int = 50) -> Dict[str, Any]:
        """Returns recent transactions, associated devices, IPs, and merchants."""
        tx_ids = self.card_to_transactions.get(target_card, [])
        tx_list = [self.transactions[t_id] for t_id in tx_ids if t_id in self.transactions]
        # Sort by timestamp desc
        tx_list.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        tx_list = tx_list[:limit_cnt]
        
        nodes = [{"v_id": target_card, "v_type": "Card", "attributes": self.cards.get(target_card, {})}]
        edges = []
        
        for tx in tx_list:
            t_id = tx["transaction_id"]
            nodes.append({"v_id": t_id, "v_type": "Transaction", "attributes": tx})
            edges.append({"from_id": target_card, "to_id": t_id, "e_type": "TRANSACTED_WITH"})
            
            dev_id = self.tx_to_device.get(t_id)
            if dev_id and dev_id in self.devices:
                nodes.append({"v_id": dev_id, "v_type": "Device", "attributes": self.devices[dev_id]})
                edges.append({"from_id": t_id, "to_id": dev_id, "e_type": "USES_DEVICE"})
                
            ip_addr = self.tx_to_ip.get(t_id)
            if ip_addr and ip_addr in self.ips:
                nodes.append({"v_id": ip_addr, "v_type": "IPAddress", "attributes": self.ips[ip_addr]})
                edges.append({"from_id": t_id, "to_id": ip_addr, "e_type": "ORIGINATED_FROM"})
                
            merc_id = self.tx_to_merchant.get(t_id)
            if merc_id and merc_id in self.merchants:
                nodes.append({"v_id": merc_id, "v_type": "Merchant", "attributes": self.merchants[merc_id]})
                edges.append({"from_id": t_id, "to_id": merc_id, "e_type": "PAID_TO"})
                
        return {"nodes": nodes, "edges": edges, "transactions": tx_list}

    def entity_links(self, target_card: str) -> Dict[str, Any]:
        """Retrieves 1-hop and 2-hop connected accounts, devices, and IPs."""
        acc_id = self.card_to_account.get(target_card)
        dev_ids = self.card_to_devices.get(target_card, [])
        ip_addrs = self.card_to_ips.get(target_card, [])
        
        linked_entities = [
            {"v_id": target_card, "v_type": "Card", "attributes": self.cards.get(target_card, {})}
        ]
        if acc_id and acc_id in self.accounts:
            linked_entities.append({"v_id": acc_id, "v_type": "Account", "attributes": self.accounts[acc_id]})
        for d in dev_ids:
            if d in self.devices:
                linked_entities.append({"v_id": d, "v_type": "Device", "attributes": self.devices[d]})
        for ip in ip_addrs:
            if ip in self.ips:
                linked_entities.append({"v_id": ip, "v_type": "IPAddress", "attributes": self.ips[ip]})
                
        return {"linked_entities": linked_entities}

    def ring_expand(self, seed_device: str, max_depth: int = 2) -> Dict[str, Any]:
        """Expands device ring across shared cards and other linked devices."""
        visited_devices = set([seed_device])
        visited_cards = set()
        edges = []
        current_devices = set([seed_device])
        
        depth = max_depth
        while current_devices and depth > 0:
            next_devices = set()
            for dev in current_devices:
                cards = self.device_to_cards.get(dev, [])
                for c in cards:
                    visited_cards.add(c)
                    edges.append({"from_id": dev, "to_id": c, "e_type": "SHARES_DEVICE"})
                    # Find other devices sharing this card
                    other_devs = self.card_to_devices.get(c, [])
                    for od in other_devs:
                        if od not in visited_devices:
                            visited_devices.add(od)
                            next_devices.add(od)
                            edges.append({"from_id": c, "to_id": od, "e_type": "SHARES_DEVICE"})
            current_devices = next_devices
            depth -= 1
            
        nodes = []
        for d in visited_devices:
            if d in self.devices:
                nodes.append({"v_id": d, "v_type": "Device", "attributes": self.devices[d]})
        for c in visited_cards:
            if c in self.cards:
                nodes.append({"v_id": c, "v_type": "Card", "attributes": self.cards[c]})
                
        return {
            "ring_nodes": nodes,
            "ring_edges": edges,
            "distinct_cards_count": len(visited_cards),
            "distinct_devices_count": len(visited_devices)
        }

    def closed_cases(self, target_card: str) -> Dict[str, Any]:
        """Returns prior closed cases touching card, account, or shared devices."""
        case_ids = set(self.entity_to_cases.get(target_card, []))
        
        # Check parent account
        acc_id = self.card_to_account.get(target_card)
        if acc_id:
            case_ids.update(self.entity_to_cases.get(acc_id, []))
            
        # Check shared devices
        for d in self.card_to_devices.get(target_card, []):
            case_ids.update(self.entity_to_cases.get(d, []))
            
        past_cases = [self.fraud_cases[cid] for cid in case_ids if cid in self.fraud_cases]
        return {"past_cases": past_cases}

    def recurring_devices(self, min_cards: int = 2) -> Dict[str, Any]:
        """Finds devices shared across >= min_cards distinct cards."""
        results = []
        for dev_id, cards in self.device_to_cards.items():
            if len(set(cards)) >= min_cards:
                dev_attrs = self.devices.get(dev_id, {}).copy()
                dev_attrs["card_count"] = len(set(cards))
                dev_attrs["linked_cards"] = list(set(cards))
                results.append({"device_id": dev_id, "attributes": dev_attrs})
        return {"recurring_devices": results}

    def upsert_fraud_case(self, case_record: Dict[str, Any]):
        """Persists a new or updated FraudCase vertex to the graph."""
        case_id = case_record["case_id"]
        self.fraud_cases[case_id] = case_record
        if "primary_card_id" in case_record:
            self.entity_to_cases.setdefault(case_record["primary_card_id"], []).append(case_id)
        if "associated_device_id" in case_record:
            self.entity_to_cases.setdefault(case_record["associated_device_id"], []).append(case_id)
