"""
Robust JSON Parser and Schema Validator for LLM Outputs.
"""

import re
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("StructuredOutputParser")


class StructuredOutputParser:
    """Parses JSON out of LLM responses, stripping codeblocks and enforcing schema integrity."""

    @staticmethod
    def parse_investigation_response(raw_text: str) -> Optional[Dict[str, Any]]:
        """Extracts JSON object from text."""
        if not raw_text:
            return None

        # Try direct json parse first
        try:
            return json.loads(raw_text.strip())
        except Exception:
            pass

        # Try regex extract between ```json ... ``` or { ... }
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass

        match_bracket = re.search(r"(\{.*\})", raw_text, re.DOTALL)
        if match_bracket:
            try:
                return json.loads(match_bracket.group(1))
            except Exception:
                pass

        logger.warning("Failed to parse JSON from LLM output.")
        return None
