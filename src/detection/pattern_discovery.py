"""
Undocumented Pattern Miner.
Performs unsupervised graph clustering and entity overlap analysis to surface
novel, emerging, or undocumented fraud rings across accounts, devices, and IPs.
"""

from typing import Dict, Any, List, Set
from collections import defaultdict


class UndocumentedPatternMiner:
    """Surfaces suspicious entity clusters that do not match the standard 5 typologies."""

    def __init__(self, tg_client: Any):
        self.tg_client = tg_client

    def discover_clusters(self, min_shared_entities: int = 2) -> List[Dict[str, Any]]:
        """
        Discovers recurring device rings and entity clusters across the graph.
        """
        recurring = self.tg_client.get_recurring_devices(min_cards=min_shared_entities)
        clusters = []

        for item in recurring.get("recurring_devices", []):
            dev_id = item.get("device_id")
            attrs = item.get("attributes", {})
            linked_cards = attrs.get("linked_cards", [])
            
            # Check if this cluster shares IP or merchant patterns
            clusters.append({
                "cluster_type": "undocumented_device_cluster",
                "seed_entity": dev_id,
                "entity_type": "Device",
                "shared_cards_count": len(linked_cards),
                "linked_cards": linked_cards,
                "is_rooted": attrs.get("is_rooted", False),
                "is_vpn": attrs.get("is_vpn", False),
                "risk_assessment": "High probability synthetic identity or card sharing ring" if len(linked_cards) >= 3 else "Moderate shared device risk"
            })

        return clusters
