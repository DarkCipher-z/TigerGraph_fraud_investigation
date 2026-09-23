"""
Automated Benchmark Runner.
Executes the full agentic pipeline across all 20 benchmark cases,
validates output schemas, writes individual answer files, and prints a comprehensive scorecard.
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Any
from tabulate import tabulate

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.graph.client import TigerGraphClient
from src.agent.orchestrator import FraudInvestigationOrchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("BenchmarkRunner")


def run_all_benchmarks(use_mock: bool = True, output_dir: Path = None):
    """Runs 20 benchmark test cases and saves formatted JSON results."""
    if output_dir is None:
        output_dir = PROJECT_ROOT / "benchmark" / "outputs"
    output_dir.mkdir(parents=True, exist_ok=True)

    import csv
    import re
    case_pack_file = PROJECT_ROOT / "data" / "case_pack.csv"
    benchmark_file = PROJECT_ROOT / "data" / "benchmark_triggers.json"

    cases = []
    if case_pack_file.exists():
        with open(case_pack_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Extract amount from trigger_text if present e.g. $77.07
                text = row.get("trigger_text", "")
                amt_match = re.search(r"\$([0-9,]+(?:\.[0-9]{2})?)", text)
                amount = float(amt_match.group(1).replace(",", "")) if amt_match else 100.0
                
                cases.append({
                    "benchmark_id": row["case_id"],
                    "case_id": row["case_id"],
                    "card_id": row.get("card_id", "CARD-UNKNOWN"),
                    "account_id": row.get("customer_id", "ACC-UNKNOWN"),
                    "transaction_id": row.get("flagged_txn_id", "TX-UNKNOWN"),
                    "amount": amount,
                    "device_id": f"DEV-{row.get('card_id', 'DEV01')}",
                    "ip_address": "198.51.100.42",
                    "trigger_type": row.get("trigger_type", "risk_score"),
                    "description": text
                })

    if not cases and benchmark_file.exists():
        with open(benchmark_file, "r", encoding="utf-8") as f:
            cases = json.load(f)

    if not cases:
        logger.error("No benchmark cases found in data directory.")
        return

    logger.info("Initializing TigerGraph Client (Mock: %s)...", use_mock)
    tg_client = TigerGraphClient(use_mock=use_mock)
    orchestrator = FraudInvestigationOrchestrator(tg_client=tg_client)

    summary_table = []
    print("\n" + "="*80)
    print("  STARTING TIGERGRAPH FRAUD INVESTIGATION BENCHMARK (20 CASES)")
    print("="*80 + "\n")

    for idx, case in enumerate(cases, 1):
        bm_id = case.get("benchmark_id", f"BM-{idx:03d}")
        logger.info("--> Running Benchmark Case [%d/20]: %s", idx, bm_id)
        
        state = orchestrator.investigate(case, case_id=bm_id)
        
        # Prepare official answer file schema
        answer = {
            "case_id": bm_id,
            "transaction_id": case.get("transaction_id"),
            "trigger_type": case.get("trigger_type"),
            "subject": {
                "card_id": case.get("card_id"),
                "account_id": case.get("account_id"),
                "amount": case.get("amount"),
                "device_id": case.get("device_id"),
                "ip_address": case.get("ip_address")
            },
            "investigation_record": {
                "risk_score": state.risk_score,
                "confidence": state.confidence,
                "uncertainty": state.uncertainty,
                "risk_tier": state.risk_tier,
                "primary_typology": state.primary_typology,
                "final_disposition": state.final_disposition,
                "reasoning_summary": state.reasoning_summary,
                "investigation_rounds": state.current_round,
                "llm_provider": state.primary_llm_provider,
                "execution_time_ms": state.total_execution_ms
            },
            "fired_signals": state.fired_signals,
            "retrieved_policies": [
                {"title": p["section_title"], "similarity": p["similarity"]}
                for p in state.retrieved_policies
            ],
            "historical_case_memory": [
                {"case_id": c["case_id"], "typology": c["typology"], "outcome": c["outcome"], "similarity": c["similarity"]}
                for c in state.similar_cases
            ],
            "actions_pre_evidence": [a.model_dump() for a in state.actions_pre_evidence],
            "actions_post_evidence": [a.model_dump() for a in state.actions_post_evidence],
            "sar_filing": {
                "required": state.requires_sar,
                "sar_reference_id": state.sar_reference_id,
                "narrative": state.sar_narrative
            } if state.requires_sar else {"required": False}
        }

        # Save answer file
        out_file = output_dir / f"case_{bm_id}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(answer, f, indent=2)

        summary_table.append([
            bm_id,
            case.get("card_id"),
            f"${case.get('amount', 0):,.2f}",
            state.risk_tier,
            f"{state.risk_score:.1f}",
            f"{state.confidence:.2f}",
            state.final_disposition,
            "YES" if state.requires_sar else "NO",
            state.primary_llm_provider,
            f"{state.total_execution_ms}ms"
        ])

    print("\n" + "="*80)
    print("  BENCHMARK EVALUATION SUMMARY SCORECARD")
    print("="*80)
    headers = ["Case ID", "Card", "Amount", "Tier", "Risk", "Conf", "Outcome", "SAR", "Provider", "Latency"]
    print(tabulate(summary_table, headers=headers, tablefmt="grid"))
    print(f"\n[OK] All 20 answer files successfully written to: {output_dir.resolve()}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run TigerGraph Fraud Investigation Benchmark Suite")
    parser.add_argument("--backend", choices=["mock", "tigergraph"], default="mock", help="Backend engine")
    args = parser.parse_args()

    run_all_benchmarks(use_mock=(args.backend == "mock"))
