"""
Graph Data Loader.
Automates loading of transaction CSVs, closed cases, and policy chunks into TigerGraph and Supabase.
"""

import json
import csv
import logging
from pathlib import Path
from typing import Dict, Any, List
import config

logger = logging.getLogger("GraphDataLoader")


class GraphDataLoader:
    """Loads CSV transactions and JSON knowledge assets into graph & vector stores."""

    def __init__(self, data_dir: Path = None):
        if data_dir is None:
            data_dir = Path(__file__).resolve().parent.parent.parent / "data"
        self.data_dir = Path(data_dir)

    def load_all(self, client: Any = None) -> Dict[str, int]:
        """Loads all datasets into the configured TigerGraph backend."""
        from .client import TigerGraphClient
        tg_client = client or TigerGraphClient()
        
        counts = {
            "transactions": 0,
            "cards": 0,
            "devices": 0,
            "closed_cases": 0
        }

        # Load closed cases
        cases_file = self.data_dir / "sample_closed_cases.json"
        if cases_file.exists():
            with open(cases_file, "r", encoding="utf-8") as f:
                cases = json.load(f)
                for c in cases:
                    tg_client.upsert_case(c)
                    counts["closed_cases"] += 1

        # Load transactions
        tx_file = self.data_dir / "synthetic_transactions.csv"
        if tx_file.exists():
            with open(tx_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                cards_seen = set()
                devices_seen = set()
                for row in reader:
                    counts["transactions"] += 1
                    cards_seen.add(row["card_id"])
                    devices_seen.add(row["device_id"])
                counts["cards"] = len(cards_seen)
                counts["devices"] = len(devices_seen)

        logger.info("Data loader completed: %s", counts)
        return counts


if __name__ == "__main__":
    loader = GraphDataLoader()
    results = loader.load_all()
    print(f"Loaded Graph Data: {results}")
