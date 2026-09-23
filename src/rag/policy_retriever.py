"""
Policy Retriever for GraphRAG Grounding.
Chunks policy documents, indexes sections, and executes vector similarity search
backed by Supabase pgvector or local in-memory vector store.
"""

import re
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np

from .embeddings import EmbeddingService
import config

logger = logging.getLogger("PolicyRetriever")


class PolicyRetriever:
    """Manages bank policy chunking, vector indexing, and semantic retrieval."""

    def __init__(self, policy_path: Optional[Path] = None):
        if policy_path is None:
            policy_path = Path(__file__).resolve().parent.parent.parent / "data" / "bank_fraud_policy.md"
        self.policy_path = Path(policy_path)
        self.embedding_service = EmbeddingService()
        self.chunks: List[Dict[str, Any]] = []
        self._load_and_chunk_policy()

    def _load_and_chunk_policy(self):
        """Splits markdown policy document into logical sections and embeds them."""
        if not self.policy_path.exists():
            logger.warning("Policy file not found at %s", self.policy_path)
            return

        with open(self.policy_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Split on headers (## or ###)
        raw_sections = re.split(r"\n(?=#{2,3}\s)", content)
        
        for idx, section in enumerate(raw_sections):
            clean_sec = section.strip()
            if not clean_sec:
                continue

            lines = clean_sec.split("\n")
            title = lines[0].replace("#", "").strip()
            body = "\n".join(lines[1:]).strip()
            
            mandatory_sar = "SAR" in clean_sec or "$5,000" in clean_sec or "FinCEN" in clean_sec
            step_up_req = "MFA" in clean_sec or "verification" in clean_sec or "Step-Up" in clean_sec
            
            emb = self.embedding_service.embed_text(clean_sec)
            
            self.chunks.append({
                "chunk_id": f"CHUNK-{idx+1:03d}",
                "section_title": title,
                "content": clean_sec,
                "mandatory_sar": mandatory_sar,
                "step_up_required": step_up_req,
                "embedding": emb
            })

        logger.info("Loaded and embedded %d policy chunks.", len(self.chunks))

    def retrieve(self, query: str, top_k: int = 3, min_similarity: float = 0.20) -> List[Dict[str, Any]]:
        """
        Retrieves the top-k most semantically relevant policy chunks for a query.
        """
        if not self.chunks:
            return []

        query_vec = np.array(self.embedding_service.embed_query(query), dtype=np.float32)
        
        scored_chunks = []
        for chunk in self.chunks:
            chunk_vec = np.array(chunk["embedding"], dtype=np.float32)
            sim = float(np.dot(query_vec, chunk_vec))
            
            if sim >= min_similarity:
                scored_chunks.append({
                    "chunk_id": chunk["chunk_id"],
                    "section_title": chunk["section_title"],
                    "content": chunk["content"],
                    "mandatory_sar": chunk["mandatory_sar"],
                    "step_up_required": chunk["step_up_required"],
                    "similarity": round(sim, 4)
                })

        # Sort by similarity descending
        scored_chunks.sort(key=lambda x: x["similarity"], reverse=True)
        return scored_chunks[:top_k]

    def retrieve_for_signals(self, signals: List[Dict[str, Any]], top_k: int = 3) -> List[Dict[str, Any]]:
        """Constructs a composite query from fired signals and returns grounded policy text."""
        if not signals:
            return self.retrieve("benign standard transaction policy", top_k=top_k)

        query_terms = [s.get("name", "") + " " + s.get("evidence", "") for s in signals]
        combined_query = " ".join(query_terms)
        return self.retrieve(combined_query, top_k=top_k)
