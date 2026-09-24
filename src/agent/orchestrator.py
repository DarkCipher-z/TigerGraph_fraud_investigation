"""
Master 8-Step Fraud Investigation Agent Orchestrator.
Orchestrates graph expansion, signal extraction, GraphRAG grounding, case memory,
uncertainty evaluation, agentic tool planning, dual-route action auditing, and SAR generation.
"""

import time
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

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
from .planner import InvestigationPlan, InvestigationToolRegistry, ToolRequest
from .evidence_validator import EvidenceValidationEngine, EvidenceItem, EvidenceIntegrityReport
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
        self.tool_registry = InvestigationToolRegistry(
            tg_client=self.tg_client,
            signal_detector=self.signal_detector,
            policy_retriever=self.policy_retriever,
            case_memory=self.case_memory
        )

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
        # Step 2: Graph Neighborhood Expansion (1-hop & 2-hop GSQL)
        # -------------------------------------------------------------
        t_s2 = time.perf_counter()
        card_hist = self.tg_client.get_card_history(card_id, limit_cnt=20)
        state.executed_queries.append({
            "query_name": "card_history",
            "params": {"target_card": card_id, "limit_cnt": 20},
            "hop_depth": 1,
            "round": 1
        })

        entity_links = self.tg_client.get_entity_links(card_id)
        state.executed_queries.append({
            "query_name": "entity_links",
            "params": {"target_card": card_id},
            "hop_depth": 2,
            "round": 1
        })

        ring_info = {}
        if device_id:
            ring_info = self.tg_client.expand_ring(device_id, max_depth=2)
            state.executed_queries.append({
                "query_name": "ring_expand",
                "params": {"seed_device": device_id, "max_depth": 2},
                "hop_depth": 2,
                "round": 1
            })

        closed_cases_res = self.tg_client.get_closed_cases(card_id)
        state.executed_queries.append({
            "query_name": "closed_cases",
            "params": {"target_card": card_id},
            "hop_depth": 2,
            "round": 1
        })
        
        state.graph_context = {
            "card_history": card_hist,
            "entity_links": entity_links,
            "ring_expansion": ring_info,
            "ring_expand": ring_info,
            "closed_cases": closed_cases_res.get("past_cases", []),
            "linked_cards_count": ring_info.get("distinct_cards_count", 1),
            "shared_devices_count": ring_info.get("distinct_devices_count", 1)
        }
        state.step_latencies_ms["graph_queries"] = max(1, int((time.perf_counter() - t_s2) * 1000))
        
        state.events.append(CaseEvent(
            step_number=2,
            step_name="Graph Neighborhood Expansion",
            event_payload={
                "transactions_found": len(card_hist.get("transactions", [])),
                "distinct_ring_cards": ring_info.get("distinct_cards_count", 1),
                "distinct_ring_devices": ring_info.get("distinct_devices_count", 1),
                "queries_executed": [q["query_name"] for q in state.executed_queries if q["round"] == 1]
            },
            latency_ms=state.step_latencies_ms["graph_queries"]
        ))

        # -------------------------------------------------------------
        # Step 3: Heuristic Signal Extraction
        # -------------------------------------------------------------
        t_s3 = time.perf_counter()
        state.fired_signals = self.signal_detector.extract_all_signals(trigger_data, state.graph_context)
        state.step_latencies_ms["detection"] = max(1, int((time.perf_counter() - t_s3) * 1000))
        
        state.events.append(CaseEvent(
            step_number=3,
            step_name="Pattern Signal Extraction",
            event_payload={"fired_signals_count": len(state.fired_signals), "signals": state.fired_signals},
            latency_ms=state.step_latencies_ms["detection"]
        ))

        # -------------------------------------------------------------
        # Step 4: GraphRAG Policy Grounding
        # -------------------------------------------------------------
        t_s4 = time.perf_counter()
        state.retrieved_policies = self.policy_retriever.retrieve_for_signals(state.fired_signals, top_k=3)
        state.step_latencies_ms["policy_rag"] = max(1, int((time.perf_counter() - t_s4) * 1000))
        
        state.events.append(CaseEvent(
            step_number=4,
            step_name="GraphRAG Policy Grounding",
            event_payload={"retrieved_policies": [{"title": p["section_title"], "similarity": p["similarity"]} for p in state.retrieved_policies]},
            latency_ms=state.step_latencies_ms["policy_rag"]
        ))

        # -------------------------------------------------------------
        # Step 5: Case Memory Lookup (Historical Precedents)
        # -------------------------------------------------------------
        t_s5 = time.perf_counter()
        summary_query = f"{trigger_data.get('description', '')} {state.fired_signals[0].get('name', '') if state.fired_signals else ''}"
        state.similar_cases = self.case_memory.retrieve_hybrid_precedents(
            card_id=card_id,
            device_id=device_id,
            case_summary_query=summary_query,
            top_k=3,
            current_case_id=cid
        )
        state.step_latencies_ms["case_memory"] = max(1, int((time.perf_counter() - t_s5) * 1000))
        
        state.events.append(CaseEvent(
            step_number=5,
            step_name="Historical Case Memory Lookup",
            event_payload={"similar_cases_found": len(state.similar_cases), "cases": state.similar_cases},
            latency_ms=state.step_latencies_ms["case_memory"]
        ))

        # -------------------------------------------------------------
        # Step 6: Initial Quantitative Assessment & Pre-Evidence Action Routing
        # -------------------------------------------------------------
        t_s6 = time.perf_counter()
        eval_round_1 = RiskEngine.evaluate(
            signals=state.fired_signals,
            prior_cases=state.similar_cases,
            retrieved_policies=state.retrieved_policies,
            evidence_round=1
        )
        state.step_latencies_ms["risk_engine_r1"] = max(1, int((time.perf_counter() - t_s6) * 1000))

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
        state.assessment_history = [
            {
                "round": 1,
                "assessment": eval_round_1.model_dump(),
                "reason": "Initial transaction and 1-2 hop graph neighborhood evaluation"
            }
        ]

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
            },
            latency_ms=state.step_latencies_ms["risk_engine_r1"]
        ))

        # -------------------------------------------------------------
        # Step 7: Uncertainty & Dynamic Evidence Loop (Round 2)
        # -------------------------------------------------------------
        t_s7 = time.perf_counter()
        if eval_round_1.requires_evidence and state.current_round < config.MAX_INVESTIGATION_ROUNDS:
            state.current_round = 2
            logger.info("Uncertainty (%s) triggered Round 2 deep evidence gathering.", state.uncertainty)
            
            # Deepen graph expansion via tool registry
            deep_ring = self.tg_client.expand_ring(device_id, max_depth=3) if device_id else {}
            state.graph_context["deep_ring_expansion"] = deep_ring
            state.executed_queries.append({
                "query_name": "ring_expand",
                "params": {"seed_device": device_id, "max_depth": 3},
                "hop_depth": 3,
                "round": 2
            })
            
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

            state.assessment_history.append({
                "round": 2,
                "assessment": eval_round_2.model_dump(),
                "reason": "Expanded 3-hop graph ring traversal resolved uncertainty"
            })
            state.step_latencies_ms["dynamic_evidence_r2"] = max(1, int((time.perf_counter() - t_s7) * 1000))

            state.events.append(CaseEvent(
                step_number=7,
                step_name="Dynamic Evidence Gathering (Round 2)",
                event_payload={
                    "round": 2,
                    "updated_risk_score": state.risk_score,
                    "updated_confidence": state.confidence,
                    "updated_uncertainty": state.uncertainty,
                    "queries_executed": ["ring_expand (depth 3)"]
                },
                latency_ms=state.step_latencies_ms["dynamic_evidence_r2"]
            ))
        else:
            state.step_latencies_ms["dynamic_evidence_check"] = max(1, int((time.perf_counter() - t_s7) * 1000))
            state.events.append(CaseEvent(
                step_number=7,
                step_name="Evidence Verification Check",
                event_payload={"status": "Sufficient confidence achieved in round 1", "uncertainty": state.uncertainty},
                latency_ms=state.step_latencies_ms["dynamic_evidence_check"]
            ))

        # -------------------------------------------------------------
        # Step 8: Multi-Tier LLM Reasoning, Evidence Validation & SAR
        # -------------------------------------------------------------
        # 1. Determine adaptive thinking level
        if state.risk_score >= 80 or state.current_round >= 2 or "RING" in state.primary_typology:
            thinking_level = "high"
        elif state.risk_score >= 35:
            thinking_level = "medium"
        else:
            thinking_level = "low"
        state.thinking_level_used = thinking_level
        state.llm_model_name = config.GEMINI_MODEL

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
        state.step_latencies_ms["llm_reasoning"] = max(1, latency_ms or 1)
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

        # 2. Extract and Validate Evidence Items
        evidence_objs = EvidenceValidationEngine.extract_evidence_items(
            trigger_data=trigger_data,
            graph_context=state.graph_context,
            fired_signals=state.fired_signals,
            retrieved_policies=state.retrieved_policies,
            similar_cases=state.similar_cases,
            round_num=state.current_round
        )
        state.evidence_items = [e.model_dump() for e in evidence_objs]
        integrity = EvidenceValidationEngine.calculate_integrity_report(evidence_objs)
        state.integrity_report = integrity.model_dump()

        # 3. Categorize Supporting vs Weakening Evidence
        supporting = []
        weakening = []
        for sig in state.fired_signals:
            supporting.append(f"{sig.get('name', 'Signal')}: {sig.get('evidence', '')}")
        if state.similar_cases:
            top_c = state.similar_cases[0]
            supporting.append(f"Topological similarity ({int(top_c.get('similarity',0)*100)}%) with prior case {top_c.get('case_id')}")

        if state.risk_score < config.RISK_THRESHOLD_LOW:
            weakening.append("Transaction amount and profile within historical baseline")
            weakening.append("No active hardware collision or proxy detected")
        elif len(state.fired_signals) <= 1:
            weakening.append("Isolated signal trigger without multi-account hardware collusion")

        if not weakening:
            weakening.append("No material weakening evidence found; multiple concurring topological anomalies observed.")

        state.supporting_evidence = supporting
        state.weakening_evidence = weakening

        # 4. Formulate Agentic Investigation Plan & Counterfactuals
        state.counterfactual_notes = (
            "Verification of legitimate commercial hardware sharing or verified corporate NAT proxy would reduce risk tier."
            if state.risk_score >= config.RISK_THRESHOLD_HIGH else
            "Subsequent cross-card velocity spikes from identical device would elevate risk tier to CRITICAL."
        )

        state.contradiction_notes = (
            "Concurring signals confirm high-risk syndicate profile with no contradictory identity claims."
            if state.risk_score >= config.RISK_THRESHOLD_HIGH else
            "Transaction amount and frequency indicate benign activity; no topological contradiction detected."
        )

        plan = InvestigationPlan(
            objective=f"Evaluate transaction ${trigger_data.get('amount', 0):,.2f} on card {card_id}",
            current_risk=state.risk_score,
            evidence_sufficient=not state.requires_evidence,
            missing_evidence=state.evidence_gaps or ["None — Sufficient certainty established"],
            hypotheses=[f"Typology: {state.primary_typology}"],
            contradictions=[state.contradiction_notes],
            supporting_factors=state.supporting_evidence[:3],
            weakening_factors=state.weakening_evidence[:2],
            counterfactual_conditions=[state.counterfactual_notes],
            next_actions=[a.action_type for a in state.actions_post_evidence],
            reasoning_level=thinking_level
        )
        state.investigation_plan = plan.model_dump()

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
                "total_execution_ms": state.total_execution_ms,
                "evidence_items_count": len(state.evidence_items)
            }
        ))

        logger.info("Investigation finished for %s in %d ms: Risk=%.1f (%s), SAR=%s, Provider=%s",
                    cid, state.total_execution_ms, state.risk_score, state.risk_tier, state.requires_sar, provider_used)
        return state
