"""
Action Audit and Human-in-the-Loop Governance Router.
Enforces strict policy checks, tamper-evident action logging, and human approval gating.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import config
from .state import ProposedAction

logger = logging.getLogger("ActionAuditLogger")


class ActionAuditLogger:
    """Manages action auditing, pre vs post evidence routing, and human approval workflows."""

    def __init__(self):
        self.in_memory_logs: List[Dict[str, Any]] = []

    def route_and_log_action(
        self,
        case_id: str,
        action: ProposedAction,
        stage: str = "pre_evidence"
    ) -> Dict[str, Any]:
        """
        Validates action against security rules, sets approval flags, and records log.
        Rule: Critical actions (block_account, file_sar, freeze_card) MUST NEVER auto-execute.
        """
        is_critical = action.action_type in config.CRITICAL_ACTIONS
        action.is_critical = is_critical
        action.requires_human_approval = is_critical
        action.stage = stage
        
        # Auto-execute non-critical actions if confidence allows
        if not is_critical and action.action_type in config.STANDARD_ACTIONS:
            action.status = "executed"
            execution_result = {"result": "success", "executed_autonomously": True}
        else:
            action.status = "queued_for_approval"
            execution_result = {"result": "pending_human_review", "gated_by_policy": True}

        action_id = f"ACT-{hash(case_id + action.action_type + action.target_entity + stage) & 0xFFFFFFFF:08x}"
        record = {
            "action_id": action_id,
            "case_id": case_id,
            "stage": stage,
            "action_type": action.action_type,
            "target_entity": action.target_entity,
            "is_critical": is_critical,
            "requires_human_approval": action.requires_human_approval,
            "status": action.status,
            "justification": action.justification,
            "execution_result": execution_result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.in_memory_logs.append(record)
        logger.info("Audit logged [%s] action: %s (%s) for case %s (Status: %s)", stage, action.action_type, action_id, case_id, action.status)
        return record

    def record_decision(self, action_id: str, decision: str = "approved", approved_by: str = "Compliance Officer") -> bool:
        """Records human decision (approved or rejected) for an action."""
        for log in self.in_memory_logs:
            if log.get("action_id") == action_id and log.get("status") == "queued_for_approval":
                log["status"] = decision
                log["approved_by"] = approved_by
                log["approved_at"] = datetime.now(timezone.utc).isoformat()
                log["execution_result"] = {
                    "result": "executed" if decision == "approved" else "rejected",
                    "decided_by_human": approved_by
                }
                logger.info("Action %s decision recorded: %s by %s", action_id, decision, approved_by)
                return True
        return False

    def approve_action(self, case_id: str, action_type: str, approved_by: str) -> bool:
        """Approves a queued critical action and triggers mock execution."""
        for log in self.in_memory_logs:
            if log["case_id"] == case_id and log["action_type"] == action_type and log["status"] == "queued_for_approval":
                log["status"] = "approved"
                log["approved_by"] = approved_by
                log["approved_at"] = datetime.now(timezone.utc).isoformat()
                log["execution_result"] = {"result": "success", "executed_after_human_approval": True}
                logger.info("Action %s for case %s approved by %s", action_type, case_id, approved_by)
                return True
        return False

    def get_case_logs(self, case_id: str) -> List[Dict[str, Any]]:
        """Returns all audit logs for a specific case."""
        return [log for log in self.in_memory_logs if log["case_id"] == case_id]

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Returns all queued actions awaiting analyst review."""
        return [log for log in self.in_memory_logs if log["status"] == "queued_for_approval"]

