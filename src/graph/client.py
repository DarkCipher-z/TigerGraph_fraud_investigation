"""
TigerGraph Client wrapper.
Provides connection pooling, health checks, GSQL query execution, and seamless mock fallback.
"""

import logging
from typing import Dict, Any, List, Optional
import config

logger = logging.getLogger("TigerGraphClient")


class TigerGraphClient:
    """
    Client interface for TigerGraph graph database.
    Connects to live TigerGraph instance via pyTigerGraph if configured,
    or falls back gracefully to high-fidelity MockGraphBackend for zero-cost offline execution.
    """

    def __init__(self, use_mock: Optional[bool] = None):
        self.use_mock = config.TG_USE_MOCK if use_mock is None else use_mock
        self.conn = None
        self.mock_backend = None

        if not self.use_mock and config.TG_HOST and config.TG_HOST != "http://127.0.0.1:9000":
            try:
                import pyTigerGraph as tg
                self.conn = tg.TigerGraphConnection(
                    host=config.TG_HOST,
                    username=config.TG_USERNAME,
                    password=config.TG_PASSWORD,
                    graphname=config.TG_GRAPH,
                    apiToken=config.TG_API_TOKEN or None,
                    secret=config.TG_SECRET or None
                )
                if config.TG_SECRET and not config.TG_API_TOKEN:
                    self.conn.getToken(config.TG_SECRET)
                logger.info("Successfully connected to live TigerGraph instance at %s", config.TG_HOST)
            except Exception as e:
                logger.warning("Failed to connect to live TigerGraph instance (%s). Falling back to MockGraphBackend.", e)
                self.use_mock = True
        else:
            self.use_mock = True

        if self.use_mock:
            from .mock_backend import MockGraphBackend
            self.mock_backend = MockGraphBackend()
            logger.info("Initialized MockGraphBackend with synthetic fraud graph dataset.")

    def is_healthy(self) -> bool:
        """Health check returns True if backend is operational."""
        if self.use_mock:
            return True
        try:
            return bool(self.conn and self.conn.ping())
        except Exception:
            return False

    def run_query(self, query_name: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Executes an installed GSQL query with parameters."""
        if self.use_mock:
            return self.mock_backend.run_installed_query(query_name, params)
        try:
            return self.conn.runInstalledQuery(query_name, params)
        except Exception as e:
            logger.error("Error executing GSQL query %s on live TigerGraph: %s. Falling back to mock.", query_name, e)
            if not self.mock_backend:
                from .mock_backend import MockGraphBackend
                self.mock_backend = MockGraphBackend()
            return self.mock_backend.run_installed_query(query_name, params)

    def get_card_history(self, target_card: str, limit_cnt: int = 50) -> Dict[str, Any]:
        """Runs card_history GSQL query."""
        results = self.run_query("card_history", {"target_card": target_card, "limit_cnt": limit_cnt})
        return results[0] if results else {"nodes": [], "edges": [], "transactions": []}

    def get_entity_links(self, target_card: str) -> Dict[str, Any]:
        """Runs entity_links GSQL query."""
        results = self.run_query("entity_links", {"target_card": target_card})
        return results[0] if results else {"linked_entities": []}

    def expand_ring(self, seed_device: str, max_depth: int = 2) -> Dict[str, Any]:
        """Runs ring_expand GSQL query."""
        results = self.run_query("ring_expand", {"seed_device": seed_device, "max_depth": max_depth})
        return results[0] if results else {"ring_nodes": [], "ring_edges": []}

    def get_closed_cases(self, target_card: str) -> Dict[str, Any]:
        """Runs closed_cases GSQL query."""
        results = self.run_query("closed_cases", {"target_card": target_card})
        return results[0] if results else {"past_cases": []}

    def get_recurring_devices(self, min_cards: int = 2) -> Dict[str, Any]:
        """Runs recurring_devices GSQL query."""
        results = self.run_query("recurring_devices", {"min_cards": min_cards})
        return results[0] if results else {"recurring_devices": []}

    def upsert_case(self, case_record: Dict[str, Any]):
        """Persists case vertex to TigerGraph / mock backend."""
        if self.use_mock:
            self.mock_backend.upsert_fraud_case(case_record)
        else:
            try:
                self.conn.upsertVertex(
                    "FraudCase",
                    case_record["case_id"],
                    attributes={
                        "trigger_type": case_record.get("trigger_type", ""),
                        "outcome": case_record.get("outcome", "inconclusive"),
                        "risk_score": float(case_record.get("risk_score", 0.0)),
                        "confidence": float(case_record.get("confidence", 0.0)),
                        "investigator_notes": case_record.get("investigator_notes", ""),
                        "sar_filed": bool(case_record.get("sar_filed", False))
                    }
                )
            except Exception as e:
                logger.error("Failed to upsert case on live TigerGraph: %s", e)
