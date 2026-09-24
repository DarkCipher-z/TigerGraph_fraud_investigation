"""
Master 8-Step Fraud Investigation Agent Orchestrator.
Orchestrates graph expansion, signal extraction, GraphRAG grounding, memory lookup,
uncertainty evaluation, dynamic evidence loop, dual-route action auditing, and SAR generation.
"""

import time
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from src.graph.client import TigerGraphClient
from src.detection.signals import SignalDetector
from src.detection.scoring import RiskEngine
from src.rag.policy_retriever import PolicyRetriever
from src.rag.case_memory import CaseMemoryService
from src.llm.circuit_breaker import ResilientLLMChain
from src.llm.prompts import PromptBuilder
from src.llm.structured_parser import StructuredOutputParser
from src.sar.generator import SARGenerator
from .state import InvestigationState, CaseEvent, ProposedAction
from .audit import ActionAuditLogger
import config

logger = logging.getLogger("FraudInvestigationOrchestrator")


class FraudInvestigationOrchestrator:
    """End-to-end 8-step autonomous fraud investigation engine."""

    def __init__(self, tg_client: Optional[TigerGraphClient] = None):
        self.tg_client = tg_client or TigerGraphClient()
        self.signal_detector = SignalDetector(self.tg_client)
        self.policy_retriever = PolicyRetriever()
        self.case_memory = CaseMemoryService(tg_client=self.tg_client)
        self.llm_chain = ResilientLLMChain()
        self.audit_logger = ActionAuditLogger()

    def investigate(self, trigger_data: Dict[str, Any], case_id: Optional[str] = None) -> InvestigationState:
        """Executes the full 8-step investigation pipeline for a suspicious transaction trigger."""
        start_time = time.time()
        
        cid = case_id or f"CASE-{trigger_data.get('benchmark_id', trigger_data.get('transaction_id', 'AUTO-01'))}"
        state = InvestigationState(case_id=cid, trigger_data=trigger_data)
        
        logger.info("Starting investigation for %s (Card: %s, Amount: $%s)", cid, trigger_data.get("card_id"), trigger_data.get("amount"))

        # -------------------------------------------------------------
        # Step 1: Trigger Ingestion & Entity Resolution
        # -------------------------------------------------------------
        card_id = trigger_data.get("card_id", "")
        account_id = trigger_data.get("account_id", "")
        device_id = trigger_data.get("device_id", "")
        
        state.events.append(CaseEvent(
            step_number=1,
            step_name="Trigger Ingestion & Entity Resolution",
            event_payload={"card_id": card_id, "account_id": account_id, "device_id": device_id, "amount": trigger_data.get("amount")}
        ))

        # -------------------------------------------------------------
        # Step 2: Graph Neighborhood Expansion (1-hop & 2-hop)
        # -------------------------------------------------------------
        card_hist = self.tg_client.get_card_history(card_id, limit_cnt=20)
        entity_links = self.tg_client.get_entity_links(card_id)
        ring_info = self.tg_client.expand_ring(device_id, max_depth=2) if device_id else {}
        
        state.graph_context = {
            "card_history": card_hist,
            "entity_links": entity_links,
            "ring_expansion": ring_info,
            "linked_cards_count": ring_info.get("distinct_cards_count", 1),
            "shared_devices_count": ring_info.get("distinct_devices_count", 1)
        }
        
        state.events.append(CaseEvent(
            step_number=2,
            step_name="Graph Neighborhood Expansion",
            event_payload={
                "transactions_found": len(card_hist.get("transactions", [])),
                "distinct_ring_cards": ring_info.get("distinct_cards_count", 1),
                "distinct_ring_devices": ring_info.get("distinct_devices_count", 1)
            }
        ))

        # -------------------------------------------------------------
        # Step 3: Heuristic Signal Extraction
        # -------------------------------------------------------------
        state.fired_signals = self.signal_detector.extract_all_signals(trigger_data, state.graph_context)
        
        state.events.append(CaseEvent(
            step_number=3,
            step_name="Pattern Signal Extraction",
            event_payload={"fired_signals_count": len(state.fired_signals), "signals": state.fired_signals}
        ))

        # -------------------------------------------------------------
        # Step 4: GraphRAG Policy Grounding
        # -------------------------------------------------------------
        state.retrieved_policies = self.policy_retriever.retrieve_for_signals(state.fired_signals, top_k=3)
        
        state.events.append(CaseEvent(
            step_number=4,
            step_name="GraphRAG Policy Grounding",
            event_payload={"retrieved_policies": [{"title": p["section_title"], "similarity": p["similarity"]} for p in state.retrieved_policies]}
        ))

        # -------------------------------------------------------------
        # Step 5: Case Memory Lookup (Historical Precedents)
        # -------------------------------------------------------------
        summary_query = f"{trigger_data.get('description', '')} {state.fired_signals[0].get('name', '') if state.fired_signals else ''}"
        state.similar_cases = self.case_memory.retrieve_hybrid_precedents(
            card_id=card_id,
            device_id=device_id,
            case_summary_query=summary_query,
            top_k=3,
            current_case_id=cid
        )
        
        state.events.append(CaseEvent(
            step_number=5,
            step_name="Historical Case Memory Lookup",
            event_payload={"similar_cases_found": len(state.similar_cases), "cases": state.similar_cases}
        ))

        # -------------------------------------------------------------
        # Step 6: Initial Quantitative Assessment & Pre-Evidence Action Routing
        # -------------------------------------------------------------
        eval_round_1 = RiskEngine.evaluate(
            signals=state.fired_signals,
            prior_cases=state.similar_cases,
            retrieved_policies=state.retrieved_policies,
            evidence_round=1
        )
        state.risk_score = eval_round_1.risk_score
        state.confidence = eval_round_1.confidence
        state.uncertainty = eval_round_1.uncertainty
        state.risk_tier = eval_round_1.risk_tier
        state.primary_typology = eval_round_1.primary_typology
        state.requires_evidence = eval_round_1.requires_evidence
        state.evidence_gaps = eval_round_1.evidence_gaps
        state.signal_contributions = eval_round_1.signal_contributions
        state.memory_adjustment = eval_round_1.memory_adjustment
        state.raw_risk = eval_round_1.raw_risk
        state.initial_assessment = eval_round_1.model_dump()

        # Propose initial pre-evidence actions
        if state.risk_score >= config.RISK_THRESHOLD_HIGH:
            act_pre = ProposedAction(
                action_type="freeze_card" if "Card" in state.primary_typology or "Testing" in state.primary_typology else "block_account",
                target_entity=card_id,
                is_critical=True,
                requires_human_approval=True,
                justification="Initial high-risk pattern detected in round 1."
            )
            state.actions_pre_evidence.append(act_pre)
            self.audit_logger.route_and_log_action(cid, act_pre, stage="pre_evidence")
        elif state.risk_score >= config.RISK_THRESHOLD_LOW:
            act_pre = ProposedAction(
                action_type="step_up_mfa",
                target_entity=card_id,
                is_critical=False,
                requires_human_approval=False,
                justification="Moderate risk requires out-of-band verification challenge."
            )
            state.actions_pre_evidence.append(act_pre)
            self.audit_logger.route_and_log_action(cid, act_pre, stage="pre_evidence")

        state.events.append(CaseEvent(
            step_number=6,
            step_name="Initial Assessment & Pre-Evidence Routing",
            event_payload={
                "risk_score": state.risk_score,
                "confidence": state.confidence,
                "uncertainty": state.uncertainty,
                "risk_tier": state.risk_tier,
                "actions_pre_evidence": [a.model_dump() for a in state.actions_pre_evidence]
            }
        ))

        # -------------------------------------------------------------
        # Step 7: Uncertainty & Dynamic Evidence Loop (Round 2)
        # -------------------------------------------------------------
        if eval_round_1.requires_evidence and state.current_round < config.MAX_INVESTIGATION_ROUNDS:
            state.current_round = 2
            logger.info("Uncertainty (%s) triggered Round 2 deep evidence gathering.", state.uncertainty)
            
            # Deepen graph expansion
            deep_ring = self.tg_client.expand_ring(device_id, max_depth=3)
            state.graph_context["deep_ring_expansion"] = deep_ring
            
            # Re-evaluate with additional evidence
            eval_round_2 = RiskEngine.evaluate(
                signals=state.fired_signals,
                prior_cases=state.similar_cases,
                retrieved_policies=state.retrieved_policies,
                evidence_round=2
            )
            state.risk_score = eval_round_2.risk_score
            state.confidence = eval_round_2.confidence
            state.uncertainty = eval_round_2.uncertainty
            state.risk_tier = eval_round_2.risk_tier
            state.signal_contributions = eval_round_2.signal_contributions
            state.memory_adjustment = eval_round_2.memory_adjustment
            state.raw_risk = eval_round_2.raw_risk
            state.requires_evidence = eval_round_2.requires_evidence
            state.evidence_gaps = eval_round_2.evidence_gaps

            state.events.append(CaseEvent(
                step_number=7,
                step_name="Dynamic Evidence Gathering (Round 2)",
                event_payload={
                    "round": 2,
                    "updated_risk_score": state.risk_score,
                    "updated_confidence": state.confidence,
                    "updated_uncertainty": state.uncertainty
                }
            ))
        else:
            state.events.append(CaseEvent(
                step_number=7,
                step_name="Evidence Verification Check",
                event_payload={"status": "Sufficient confidence achieved in round 1", "uncertainty": state.uncertainty}
            ))

        # -------------------------------------------------------------
        # Step 8: Multi-Tier LLM Reasoning, Post-Evidence Routing & SAR
        # -------------------------------------------------------------
        graph_summary = {
            "linked_cards_count": state.graph_context.get("linked_cards_count", 1),
            "shared_devices_count": state.graph_context.get("shared_devices_count", 1),
            "neighbors": state.graph_context.get("entity_links", {}).get("linked_entities", [])[:5]
        }

        prompt = PromptBuilder.build_investigation_prompt(
            case_id=cid,
            trigger_data=trigger_data,
            graph_summary=graph_summary,
            fired_signals=state.fired_signals,
            retrieved_policies=state.retrieved_policies,
            similar_cases=state.similar_cases,
            round_number=state.current_round
        )

        raw_llm_text, provider_used, latency_ms = self.llm_chain.generate(prompt)
        state.primary_llm_provider = provider_used
        parsed_llm = StructuredOutputParser.parse_investigation_response(raw_llm_text) or {}

        state.reasoning_summary = parsed_llm.get("reasoning_summary", "Automated analysis completed based on graph topology and fired signals.")
        state.final_disposition = parsed_llm.get("recommended_disposition", "confirmed_fraud" if state.risk_score >= config.RISK_THRESHOLD_HIGH else "cleared_benign")
        
        # Route Post-Evidence Proposed Actions
        llm_actions = parsed_llm.get("proposed_actions", [])
        if llm_actions:
            for act_dict in llm_actions:
                act = ProposedAction(
                    action_type=act_dict.get("action_type", "flag_for_review"),
                    target_entity=act_dict.get("target_entity", card_id),
                    is_critical=act_dict.get("is_critical", False),
                    requires_human_approval=act_dict.get("requires_human_approval", False),
                    justification=act_dict.get("justification", "")
                )
                state.actions_post_evidence.append(act)
                self.audit_logger.route_and_log_action(cid, act, stage="post_evidence")
        else:
            # Fallback deterministic post-evidence actions
            if state.risk_score >= config.RISK_THRESHOLD_HIGH:
                act = ProposedAction(
                    action_type="freeze_card",
                    target_entity=card_id,
                    is_critical=True,
                    requires_human_approval=True,
                    justification="Confirmed high risk fraud post-evidence."
                )
                state.actions_post_evidence.append(act)
                self.audit_logger.route_and_log_action(cid, act, stage="post_evidence")

        # Check SAR requirement (Mandatory if amount >= $5,000 and high risk or explicitly flagged)
        amt = float(trigger_data.get("amount", 0.0))
        requires_sar = parsed_llm.get("requires_sar_filing", False) or (amt >= config.SAR_MIN_AMOUNT_THRESHOLD and state.risk_score >= config.RISK_THRESHOLD_HIGH)
        state.requires_sar = requires_sar

        if requires_sar:
            sar_doc = SARGenerator.generate_sar(cid, trigger_data, state)
            state.sar_narrative = sar_doc["narrative"]
            state.sar_reference_id = sar_doc["sar_reference_id"]
            
            # Log SAR action in audit log
            sar_act = ProposedAction(
                action_type="file_sar",
                target_entity="FinCEN / FIU",
                is_critical=True,
                requires_human_approval=True,
                justification=f"Mandatory SAR filing for suspicious activity totaling ${amt:,.2f}."
            )
            state.actions_post_evidence.append(sar_act)
            self.audit_logger.route_and_log_action(cid, sar_act, stage="post_evidence")

        # Persist case back into TigerGraph FraudCase vertex
        self.tg_client.upsert_case({
            "case_id": cid,
            "trigger_type": trigger_data.get("trigger_type", "unknown"),
            "outcome": state.final_disposition,
            "risk_score": state.risk_score,
            "confidence": state.confidence,
            "primary_card_id": card_id,
            "associated_device_id": device_id,
            "investigator_notes": state.reasoning_summary,
            "sar_filed": state.requires_sar
        })

        state.status = "resolved_fraud" if state.final_disposition == "confirmed_fraud" else ("resolved_cleared" if state.final_disposition == "cleared_benign" else "under_review")
        state.total_execution_ms = int((time.time() - start_time) * 1000)

        state.events.append(CaseEvent(
            step_number=8,
            step_name="Final Recommendation, Post-Evidence Routing & SAR Synthesis",
            llm_provider=provider_used,
            latency_ms=latency_ms,
            event_payload={
                "final_disposition": state.final_disposition,
                "primary_typology": state.primary_typology,
                "requires_sar": state.requires_sar,
                "sar_reference_id": state.sar_reference_id,
                "actions_post_evidence": [a.model_dump() for a in state.actions_post_evidence],
                "total_execution_ms": state.total_execution_ms
            }
        ))

        logger.info("Investigation finished for %s in %d ms: Risk=%.1f (%s), SAR=%s, Provider=%s",
                    cid, state.total_execution_ms, state.risk_score, state.risk_tier, state.requires_sar, provider_used)
        return state
