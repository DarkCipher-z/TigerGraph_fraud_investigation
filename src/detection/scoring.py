"""
Risk, Confidence, and Uncertainty Scoring Engine.
Computes mathematically grounded risk assessment metrics and uncertainty gating.
"""

from typing import Dict, Any, List
from pydantic import BaseModel, Field
import config


class AssessmentResult(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    uncertainty: float = Field(..., ge=0.0, le=1.0)
    risk_tier: str  # LOW, MEDIUM, HIGH, CRITICAL
    primary_typology: str
    requires_evidence: bool
    fired_signals: List[Dict[str, Any]]
    evidence_gaps: List[str]


class RiskEngine:
    """
    Computes risk score, confidence, and uncertainty from fired signals,
    graph neighborhood density, and historical case precedents.
    """

    @staticmethod
    def evaluate(
        signals: List[Dict[str, Any]],
        prior_cases: List[Dict[str, Any]] = None,
        retrieved_policies: List[Dict[str, Any]] = None,
        evidence_round: int = 1
    ) -> AssessmentResult:
        """
        Evaluates signals, applying signal severity, weights, and memory adjustments.
        """
        prior_cases = prior_cases or []
        retrieved_policies = retrieved_policies or []

        if not signals:
            # Benign baseline
            return AssessmentResult(
                risk_score=15.0,
                confidence=0.90,
                uncertainty=0.10,
                risk_tier="LOW",
                primary_typology="Benign Activity",
                requires_evidence=False,
                fired_signals=[],
                evidence_gaps=[]
            )

        # 1. Compute weighted risk score
        total_weight = sum(s.get("weight", 0.1) for s in signals)
        if total_weight > 0:
            raw_risk = sum(s.get("severity", 50.0) * s.get("weight", 0.1) for s in signals) / total_weight
        else:
            raw_risk = 50.0

        # 2. Adjust with historical case memory (if prior fraud case exists on same ring/card)
        memory_boost = 0.0
        for pc in prior_cases:
            outcome = pc.get("outcome", "")
            sim = pc.get("similarity", 0.8)
            if outcome == "confirmed_fraud":
                memory_boost += (10.0 * sim)
            elif outcome == "cleared_benign":
                memory_boost -= (8.0 * sim)

        adjusted_risk = max(5.0, min(99.0, raw_risk + memory_boost))

        # 3. Compute confidence score
        # Confidence increases with more concurring signals, grounded policy chunks, and evidence rounds
        base_confidence = 0.60 + min(0.25, len(signals) * 0.08)
        if retrieved_policies:
            base_confidence += min(0.10, len(retrieved_policies) * 0.03)
        if evidence_round > 1:
            base_confidence += 0.08
        confidence = max(0.40, min(0.98, base_confidence))

        # 4. Compute uncertainty metric
        # Uncertainty is high when risk is borderline (around 40-70) or confidence is low
        boundary_distance = abs(adjusted_risk - 50.0) / 50.0  # 0 at boundary (50), 1 at extremes (0 or 100)
        uncertainty = max(0.05, min(0.95, (1.0 - confidence) * 0.7 + (1.0 - boundary_distance) * 0.3))

        # 5. Check if additional evidence should be gathered
        requires_evidence = False
        evidence_gaps = []

        for s in signals:
            if s.get("requires_evidence", False):
                evidence_gaps.append(f"Verification needed for {s.get('name')}: {s.get('evidence')}")
                if uncertainty >= config.UNCERTAINTY_EVIDENCE_REQ and evidence_round < config.MAX_INVESTIGATION_ROUNDS:
                    requires_evidence = True

        # Determine risk tier
        if adjusted_risk >= 85.0:
            risk_tier = "CRITICAL"
        elif adjusted_risk >= config.RISK_THRESHOLD_HIGH:
            risk_tier = "HIGH"
        elif adjusted_risk <= config.RISK_THRESHOLD_LOW:
            risk_tier = "LOW"
        else:
            risk_tier = "MEDIUM"

        primary_typology = signals[0].get("name", "Unknown Pattern") if signals else "General Review"

        return AssessmentResult(
            risk_score=round(adjusted_risk, 2),
            confidence=round(confidence, 3),
            uncertainty=round(uncertainty, 3),
            risk_tier=risk_tier,
            primary_typology=primary_typology,
            requires_evidence=requires_evidence,
            fired_signals=signals,
            evidence_gaps=evidence_gaps
        )
