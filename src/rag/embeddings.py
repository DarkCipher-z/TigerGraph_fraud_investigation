"""
Embedding Service for GraphRAG and Case Memory.
Integrates Google AI Studio text-embedding-004 with a deterministic local fallback.
"""

import hashlib
import logging
import numpy as np
from typing import List, Union
import config

logger = logging.getLogger("EmbeddingService")


class EmbeddingService:
    """Generates 768-dimensional normalized embeddings for policy chunks and case summaries."""

    def __init__(self):
        self.api_key = config.GEMINI_API_KEY
        self.model_name = config.EMBEDDING_MODEL
        self._client_initialized = False

        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client_initialized = True
                logger.info("Google AI Studio embedding client configured successfully.")
            except Exception as e:
                logger.warning("Failed to initialize Google GenAI embeddings: %s. Using local deterministic fallback.", e)

    def embed_text(self, text: str) -> List[float]:
        """Generates 768-dim embedding for a single string."""
        if self._client_initialized:
            try:
                import google.generativeai as genai
                result = genai.embed_content(
                    model=self.model_name,
                    content=text,
                    task_type="retrieval_document"
                )
                embedding = result["embedding"]
                return embedding
            except Exception as e:
                logger.warning("Gemini embedding API call failed (%s). Disabling API client and using local fallback.", e)
                self._client_initialized = False

        return self._local_deterministic_embedding(text)

    def embed_query(self, query: str) -> List[float]:
        """Generates 768-dim embedding for search query."""
        if self._client_initialized:
            try:
                import google.generativeai as genai
                result = genai.embed_content(
                    model=self.model_name,
                    content=query,
                    task_type="retrieval_query"
                )
                return result["embedding"]
            except Exception as e:
                logger.warning("Gemini query embedding failed: %s. Disabling API client and using local fallback.", e)
                self._client_initialized = False

        return self._local_deterministic_embedding(query)

    def _local_deterministic_embedding(self, text: str, dim: int = 768) -> List[float]:
        """
        Deterministic pseudo-semantic vector generation for zero-cost offline execution.
        Maps text tokens and n-grams into a normalized 768-dimensional float array.
        """
        words = text.lower().split()
        vec = np.zeros(dim, dtype=np.float32)
        
        for i, word in enumerate(words):
            # Deterministic hash seed
            h = int(hashlib.sha256(word.encode("utf-8")).hexdigest()[:8], 16)
            idx = h % dim
            sign = 1.0 if (h % 2 == 0) else -1.0
            vec[idx] += sign * (1.0 / (1.0 + i * 0.05))
            
            # Additional semantic grouping for fraud keywords
            if any(k in word for k in ["ring", "device", "emulator", "shared"]):
                vec[10:20] += 0.5
            if any(k in word for k in ["ato", "takeover", "password", "credential", "email"]):
                vec[20:30] += 0.5
            if any(k in word for k in ["sar", "fincen", "5000", "regulatory", "report"]):
                vec[30:40] += 0.5
            if any(k in word for k in ["test", "bin", "micro", "charity"]):
                vec[40:50] += 0.5
            if any(k in word for k in ["velocity", "burst", "rapid", "frequency"]):
                vec[50:60] += 0.5

        # L2 normalize
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        else:
            vec[0] = 1.0

        return vec.tolist()
