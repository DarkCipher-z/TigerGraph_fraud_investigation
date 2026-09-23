"""
Hybrid Case Memory Service.
Combines graph entity overlap matching with semantic vector similarity
to retrieve relevant prior closed cases and directly inform new investigations.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np

from .embeddings import EmbeddingService

logger = logging.getLogger("CaseMemoryService")


class CaseMemoryService:
    """Hybrid memory store combining graph topological links and vector embeddings."""

    def __init__(self, data_dir: Optional[Path] = None, tg_client: Any = None):
        if data_dir is None:
            data_dir = Path(__file__).resolve().parent.parent.parent / "data"
        self.data_dir = Path(data_dir)
        self.tg_client = tg_client
        self.embedding_service = EmbeddingService()
        self.indexed_cases: List[Dict[str, Any]] = []
        self._load_and_index_closed_cases()

    def _load_and_index_closed_cases(self):
        """Loads labeled closed cases from CSV history or JSON sample and computes summary embeddings."""
        history_csv = self.data_dir / "closed_cases_history.csv"
        sample_json = self.data_dir / "sample_closed_cases.json"

        if history_csv.exists():
            import csv
            with open(history_csv, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    summary = f"{row.get('pattern', '')}: {row.get('analyst_notes', '')}"
                    emb = self.embedding_service.embed_text(summary)
                    
                    self.indexed_cases.append({
                        "case_id": row["case_id"],
                        "trigger_type": row.get("pattern", "unknown"),
                        "primary_card_id": row.get("card_id", ""),
                        "primary_account_id": row.get("customer_id", ""),
                        "associated_device_id": "",
                        "outcome": "confirmed_fraud" if "fraud" in row.get("outcome", "").lower() else "cleared_benign",
                        "risk_score": 90.0 if "fraud" in row.get("outcome", "").lower() else 20.0,
                        "confidence": 0.92,
                        "typology": row.get("pattern", "Fraud Pattern"),
                        "summary": summary,
                        "sar_filed": row.get("report_filed", "No").lower() == "yes",
                        "embedding": emb
                    })

        if sample_json.exists():
            with open(sample_json, "r", encoding="utf-8") as f:
                cases = json.load(f)

            for c in cases:
                summary = f"{c.get('typology', '')} - {c.get('investigator_notes', '')}"
                emb = self.embedding_service.embed_text(summary)
                
                self.indexed_cases.append({
                    "case_id": c["case_id"],
                    "trigger_type": c.get("trigger_type", ""),
                    "primary_card_id": c.get("primary_card_id", ""),
                    "associated_device_id": c.get("associated_device_id", ""),
                    "outcome": c.get("outcome", "confirmed_fraud"),
                    "risk_score": c.get("risk_score", 90.0),
                    "confidence": c.get("confidence", 0.9),
                    "typology": c.get("typology", ""),
                    "summary": summary,
                    "sar_filed": c.get("sar_filed", False),
                    "embedding": emb
                })

        logger.info("Indexed %d historical closed cases into memory.", len(self.indexed_cases))

    def retrieve_hybrid_precedents(
        self,
        card_id: str,
        device_id: str,
        case_summary_query: str,
        top_k: int = 3,
        current_case_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Executes hybrid memory retrieval:
        1. Graph entity overlap (cards, devices)
        2. Vector cosine similarity on summary text
        Combined into a single composite ranked list.
        """
        if not self.indexed_cases:
            return []

        query_vec = np.array(self.embedding_service.embed_query(case_summary_query), dtype=np.float32)
        
        # Check graph overlaps if client is available
        graph_linked_case_ids = set()
        if self.tg_client:
            graph_cases = self.tg_client.get_closed_cases(card_id)
            for pc in graph_cases.get("past_cases", []):
                graph_linked_case_ids.add(pc.get("case_id"))

        results = []
        for case in self.indexed_cases:
            # Rule: An unresolved or current case must never appear in its own memory lookup
            if current_case_id and case["case_id"] == current_case_id:
                continue

            case_vec = np.array(case["embedding"], dtype=np.float32)
            vector_sim = float(np.dot(query_vec, case_vec))
            
            # Graph overlap bonus
            is_graph_linked = (case["case_id"] in graph_linked_case_ids) or \
                              (case["primary_card_id"] == card_id) or \
                              (case["associated_device_id"] == device_id)
                              
            hybrid_score = vector_sim + (0.35 if is_graph_linked else 0.0)

            if hybrid_score > 0.30:
                results.append({
                    "case_id": case["case_id"],
                    "outcome": case["outcome"],
                    "typology": case["typology"],
                    "summary": case["summary"],
                    "sar_filed": case["sar_filed"],
                    "is_graph_linked": is_graph_linked,
                    "similarity": round(hybrid_score, 3)
                })

        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]
