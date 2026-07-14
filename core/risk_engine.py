from typing import Dict, List
from config import RISK_WEIGHTS
from datetime import datetime
import asyncio # Import asyncio

async def calculate_composite_risk(
    individual_tx_result: Dict,
    o2p_result: Dict,
    backrun_result: Dict,
    drift_result: Dict,
    api_exhaustion_result: Dict,
    skill_infection_result: Dict,
    chain_validation_result: Dict
) -> Dict:
    """
    Combines all security signals into a composite risk score and final verdict.

    Args:
        individual_tx_result (Dict): Result from OKX transaction scan.
                                     Expected keys: "risk_level" (e.g., "LOW", "MEDIUM", "HIGH", "CRITICAL")
        o2p_result (Dict): Result from O2P pattern detection.
                           Expected keys: "o2p_score" (float), "overall_flag" (e.g., "CLEAN", "ACCUMULATING", "CRITICAL_O2P")
        backrun_result (Dict): Result from backrun risk detection.
                               Expected keys: "backrun_risk" (e.g., "LOW", "MEDIUM", "HIGH", "CRITICAL")
        drift_result (Dict): Result from behavioral drift detection.
                             Expected keys: "drift_score" (float), "overall_flag" (e.g., "NORMAL", "DRIFTING", "CRITICAL_DRIFT")
        api_exhaustion_result (Dict): Result from API exhaustion detection.
                                      Expected keys: "risk" (e.g., "NONE", "LOW", "WARNING", "CRITICAL")
        skill_infection_result (Dict): Result from skill infection detection.
                                       Expected keys: "risk" (e.g., "NONE", "CRITICAL")
        chain_validation_result (Dict): Result from payment chain validation.
                                        Expected keys: "risk" (e.g., "NONE", "WARNING", "CRITICAL")

    Returns:
        Dict: A dictionary containing the composite score, verdict, action,
              component scores, and flags.
    """
    component_scores = {}
    all_flags = []
    critical_flags = []

    # Map individual_tx_result risk_level to a 0-100 score
    individual_tx_score_map = {
        "LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 90, "UNKNOWN": 50
    }
    individual_tx_score = individual_tx_score_map.get(individual_tx_result.get("risk_level", "UNKNOWN"), 50)
    component_scores["individual_tx"] = individual_tx_score
    if individual_tx_result.get("risk_level") == "CRITICAL":
        critical_flags.append(f"Individual TX: {individual_tx_result.get('risk_level')} - {individual_tx_result.get('risk_items', ['No specific items'])}")
    if individual_tx_result.get("risk_level") != "LOW":
        all_flags.append(f"Individual TX: {individual_tx_result.get('risk_level')}")


    # O2P Pattern Score
    o2p_score = o2p_result.get("o2p_score", 0.0)
    component_scores["pattern_score"] = o2p_score
    if o2p_result.get("overall_flag") == "CRITICAL_O2P":
        critical_flags.extend(o2p_result.get("flags", []))
    all_flags.extend(o2p_result.get("flags", []))

    # Backrun Risk Score
    backrun_score_map = {
        "LOW": 10, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 90, "UNKNOWN": 50
    }
    backrun_score = backrun_score_map.get(backrun_result.get("backrun_risk", "UNKNOWN"), 50)
    component_scores["backrun_risk"] = backrun_score
    if backrun_result.get("backrun_risk") == "CRITICAL":
        critical_flags.append(f"Backrun Risk: {backrun_result.get('flag')}")
    if backrun_result.get("backrun_risk") != "LOW":
        all_flags.append(f"Backrun Risk: {backrun_result.get('flag')}")

    # Behavioral Drift Score
    drift_score = drift_result.get("drift_score", 0.0)
    component_scores["behavioral_drift"] = drift_score
    if drift_result.get("overall_flag") == "CRITICAL_DRIFT":
        critical_flags.extend(drift_result.get("flags", []))
    all_flags.extend(drift_result.get("flags", []))

    # API Exhaustion Score
    api_exhaustion_score_map = {
        "NONE": 0, "LOW": 10, "WARNING": 60, "CRITICAL": 90
    }
    api_exhaustion_score = api_exhaustion_score_map.get(api_exhaustion_result.get("risk", "NONE"), 0)
    component_scores["api_exhaustion"] = api_exhaustion_score
    if api_exhaustion_result.get("risk") == "CRITICAL":
        critical_flags.append(f"API Exhaustion: {api_exhaustion_result.get('flag')}")
    if api_exhaustion_result.get("risk") != "NONE":
        all_flags.append(f"API Exhaustion: {api_exhaustion_result.get('flag')}")

    # Skill Infection Score
    skill_infection_score_map = {
        "NONE": 0, "CRITICAL": 100
    }
    skill_infection_score = skill_infection_score_map.get(skill_infection_result.get("risk", "NONE"), 0)
    component_scores["skill_infection"] = skill_infection_score
    if skill_infection_result.get("risk") == "CRITICAL":
        critical_flags.append(f"Skill Infection: {skill_infection_result.get('flag')}")
    if skill_infection_result.get("risk") != "NONE":
        all_flags.append(f"Skill Infection: {skill_infection_result.get('flag')}")

    # Chain Validation Score
    chain_validation_score_map = {
        "NONE": 0, "SAFE": 0, "WARNING": 50, "CRITICAL": 100
    }
    chain_validation_score = chain_validation_score_map.get(chain_validation_result.get("risk", "NONE"), 0)
    component_scores["chain_validation"] = chain_validation_score
    if chain_validation_result.get("risk") == "CRITICAL":
        critical_flags.append(f"Chain Validation: {chain_validation_result.get('flag')}")
    if chain_validation_result.get("risk") != "NONE":
        all_flags.append(f"Chain Validation: {chain_validation_result.get('flag')}")


    # Calculate composite score using weights
    composite_score = (
        component_scores.get("individual_tx", 0) * RISK_WEIGHTS["individual_tx"] +
        component_scores.get("pattern_score", 0) * RISK_WEIGHTS["pattern_score"] +
        component_scores.get("behavioral_drift", 0) * RISK_WEIGHTS["behavioral_drift"] +
        component_scores.get("chain_validation", 0) * RISK_WEIGHTS["chain_validation"] +
        component_scores.get("backrun_risk", 0) * (1 - sum(RISK_WEIGHTS.values())) # Distribute remaining weight
    )
    # Clamp composite score between 0 and 100
    composite_score = max(0.0, min(100.0, composite_score))

    verdict = "SAFE"
    action = "ALLOW"

    if composite_score >= 75 or critical_flags:
        verdict = "BLOCK"
        action = "BLOCK"
    elif composite_score >= 45 or any("WARNING" in flag for flag in all_flags):
        verdict = "WARN"
        action = "REVIEW"

    # Remove duplicate flags and sort critical flags first
    all_flags = sorted(list(set(all_flags)), key=lambda x: x.startswith("CRITICAL"), reverse=True)
    critical_flags = sorted(list(set(critical_flags)), key=lambda x: x.startswith("CRITICAL"), reverse=True)


    return {
        "composite_score": float(composite_score),
        "verdict": verdict,
        "action": action,
        "component_scores": component_scores,
        "all_flags": all_flags,
        "critical_flags": critical_flags,
        "analysis_timestamp": datetime.now().isoformat()
    }

# Self-test block
async def main():
    print("Running core/risk_engine.py self-test...")
    # Mock results for testing
    mock_individual_tx_safe = {"risk_level": "LOW", "risk_items": []}
    mock_individual_tx_warn = {"risk_level": "MEDIUM", "risk_items": [{"label": "SuspiciousContract", "detail": "Contract has low reputation"}]}
    mock_individual_tx_block = {"risk_level": "CRITICAL", "risk_items": [{"label": "MaliciousContract", "detail": "Known phishing contract"}]}

    mock_o2p_clean = {"o2p_score": 10.0, "overall_flag": "CLEAN", "flags": []}
    mock_o2p_accumulating = {"o2p_score": 40.0, "overall_flag": "ACCUMULATING", "flags": ["WARNING: Elevated approval count (5) detected."]}
    mock_o2p_critical = {"o2p_score": 70.0, "overall_flag": "CRITICAL_O2P", "flags": ["CRITICAL: High approval count (12) detected."]}

    mock_backrun_low = {"backrun_risk": "LOW", "liquidity_ratio": 0.001, "pool_liquidity_usd": 1000000.0, "trade_amount_usd": 1000.0, "flag": "LOW: Trade amount is a small percentage of pool liquidity, low backrun risk."}
    mock_backrun_high = {"backrun_risk": "HIGH", "liquidity_ratio": 0.1, "pool_liquidity_usd": 100000.0, "trade_amount_usd": 10000.0, "flag": "WARNING: Trade amount is a high percentage of pool liquidity, indicating elevated backrun risk."}
    mock_backrun_critical = {"backrun_risk": "CRITICAL", "liquidity_ratio": 0.2, "pool_liquidity_usd": 100000.0, "trade_amount_usd": 20000.0, "flag": "CRITICAL: Trade amount is a very high percentage of pool liquidity, indicating high backrun risk."}

    mock_drift_normal = {"drift_score": 15.0, "overall_flag": "NORMAL", "flags": []}
    mock_drift_drifting = {"drift_score": 40.0, "overall_flag": "DRIFTING", "flags": ["WARNING: Transaction amount (Z-score 2.50) significantly deviates from baseline."]}
    mock_drift_critical = {"drift_score": 70.0, "overall_flag": "CRITICAL_DRIFT", "flags": ["CRITICAL: Risk score velocity (3.00) critically increasing."]}

    mock_api_exhaustion_none = {"risk": "NONE", "failure_count": 0, "failure_rate_per_hour": 0.0, "flag": "No API exhaustion risk detected."}
    mock_api_exhaustion_warn = {"risk": "WARNING", "failure_count": 3, "failure_rate_per_hour": 3.0, "flag": "WARNING: Elevated security API failures (3) detected, potential exhaustion attempt."}
    mock_api_exhaustion_critical = {"risk": "CRITICAL", "failure_count": 5, "failure_rate_per_hour": 5.0, "flag": "CRITICAL: Security API exhaustion detected with 5 failures."}

    mock_skill_infection_none = {"risk": "NONE", "infected_skills": [], "flag": "No skill infection detected."}
    mock_skill_infection_critical = {"risk": "CRITICAL", "infected_skills": ["malicious_skill"], "flag": "CRITICAL: Agent behavior changed after calling skill(s): malicious_skill. Potential skill infection."}

    mock_chain_validation_safe = {"valid": True, "risk": "SAFE", "chain_length": 1, "total_spent_usd": 10.0, "budget_remaining_usd": 90.0, "flag": "Payment chain is valid."}
    mock_chain_validation_warn = {"valid": False, "risk": "WARNING", "chain_length": 2, "total_spent_usd": 110.0, "budget_remaining_usd": -10.0, "flag": "WARNING: Total spent ($110.00 USD) exceeds authorized budget ($100.00 USD)."}
    mock_chain_validation_critical = {"valid": False, "risk": "CRITICAL", "chain_length": 4, "total_spent_usd": 50.0, "budget_remaining_usd": 50.0, "flag": "CRITICAL: Payment chain length (4) exceeds maximum authorized hops (3)."}


    # Test 1: All safe
    print("\n--- Test 1: All Safe ---")
    result_safe = await calculate_composite_risk(
        mock_individual_tx_safe, mock_o2p_clean, mock_backrun_low, mock_drift_normal,
        mock_api_exhaustion_none, mock_skill_infection_none, mock_chain_validation_safe
    )
    print(f"Result Safe: {result_safe}")
    assert result_safe["verdict"] == "SAFE"
    assert result_safe["action"] == "ALLOW"
    assert result_safe["composite_score"] < 45
    assert not result_safe["critical_flags"]

    # Test 2: Some warnings, overall WARN
    print("\n--- Test 2: Some Warnings ---")
    result_warn = await calculate_composite_risk(
        mock_individual_tx_warn, mock_o2p_accumulating, mock_backrun_high, mock_drift_drifting,
        mock_api_exhaustion_warn, mock_skill_infection_none, mock_chain_validation_warn
    )
    print(f"Result Warn: {result_warn}")
    assert result_warn["verdict"] == "WARN"
    assert result_warn["action"] == "REVIEW"
    assert result_warn["composite_score"] >= 45
    assert not result_warn["critical_flags"]
    assert any("WARNING" in flag for flag in result_warn["all_flags"])

    # Test 3: One critical flag, overall BLOCK
    print("\n--- Test 3: One Critical Flag ---")
    result_block_critical_tx = await calculate_composite_risk(
        mock_individual_tx_block, mock_o2p_clean, mock_backrun_low, mock_drift_normal,
        mock_api_exhaustion_none, mock_skill_infection_none, mock_chain_validation_safe
    )
    print(f"Result Block (Critical TX): {result_block_critical_tx}")
    assert result_block_critical_tx["verdict"] == "BLOCK"
    assert result_block_critical_tx["action"] == "BLOCK"
    assert any("CRITICAL" in flag for flag in result_block_critical_tx["critical_flags"])

    # Test 4: Critical O2P, overall BLOCK
    print("\n--- Test 4: Critical O2P ---")
    result_block_o2p = await calculate_composite_risk(
        mock_individual_tx_safe, mock_o2p_critical, mock_backrun_low, mock_drift_normal,
        mock_api_exhaustion_none, mock_skill_infection_none, mock_chain_validation_safe
    )
    print(f"Result Block (Critical O2P): {result_block_o2p}")
    assert result_block_o2p["verdict"] == "BLOCK"
    assert result_block_o2p["action"] == "BLOCK"
    assert any("CRITICAL" in flag for flag in result_block_o2p["critical_flags"])

    # Test 5: Critical Drift, overall BLOCK
    print("\n--- Test 5: Critical Drift ---")
    result_block_drift = await calculate_composite_risk(
        mock_individual_tx_safe, mock_o2p_clean, mock_backrun_low, mock_drift_critical,
        mock_api_exhaustion_none, mock_skill_infection_none, mock_chain_validation_safe
    )
    print(f"Result Block (Critical Drift): {result_block_drift}")
    assert result_block_drift["verdict"] == "BLOCK"
    assert result_block_drift["action"] == "BLOCK"
    assert any("CRITICAL" in flag for flag in result_block_drift["critical_flags"])

    # Test 6: Critical API Exhaustion, overall BLOCK
    print("\n--- Test 6: Critical API Exhaustion ---")
    result_block_api_exhaustion = await calculate_composite_risk(
        mock_individual_tx_safe, mock_o2p_clean, mock_backrun_low, mock_drift_normal,
        mock_api_exhaustion_critical, mock_skill_infection_none, mock_chain_validation_safe
    )
    print(f"Result Block (Critical API Exhaustion): {result_block_api_exhaustion}")
    assert result_block_api_exhaustion["verdict"] == "BLOCK"
    assert result_block_api_exhaustion["action"] == "BLOCK"
    assert any("CRITICAL" in flag for flag in result_block_api_exhaustion["critical_flags"])

    # Test 7: Critical Skill Infection, overall BLOCK
    print("\n--- Test 7: Critical Skill Infection ---")
    result_block_skill_infection = await calculate_composite_risk(
        mock_individual_tx_safe, mock_o2p_clean, mock_backrun_low, mock_drift_normal,
        mock_api_exhaustion_none, mock_skill_infection_critical, mock_chain_validation_safe
    )
    print(f"Result Block (Critical Skill Infection): {result_block_skill_infection}")
    assert result_block_skill_infection["verdict"] == "BLOCK"
    assert result_block_skill_infection["action"] == "BLOCK"
    assert any("CRITICAL" in flag for flag in result_block_skill_infection["critical_flags"])

    # Test 8: Critical Chain Validation, overall BLOCK
    print("\n--- Test 8: Critical Chain Validation ---")
    result_block_chain_validation = await calculate_composite_risk(
        mock_individual_tx_safe, mock_o2p_clean, mock_backrun_low, mock_drift_normal,
        mock_api_exhaustion_none, mock_skill_infection_none, mock_chain_validation_critical
    )
    print(f"Result Block (Critical Chain Validation): {result_block_chain_validation}")
    assert result_block_chain_validation["verdict"] == "BLOCK"
    assert result_block_chain_validation["action"] == "BLOCK"
    assert any("CRITICAL" in flag for flag in result_block_chain_validation["critical_flags"])

    # Test 9: All components contributing to a high score, but no single critical flag
    print("\n--- Test 9: High Score, No Single Critical Flag ---")
    result_high_score = await calculate_composite_risk(
        mock_individual_tx_warn, mock_o2p_accumulating, mock_backrun_high, mock_drift_drifting,
        mock_api_exhaustion_warn, mock_skill_infection_none, mock_chain_validation_warn
    )
    print(f"Result High Score: {result_high_score}")
    assert result_high_score["verdict"] == "WARN"
    assert result_high_score["action"] == "REVIEW"
    assert result_high_score["composite_score"] >= 45
    assert not result_high_score["critical_flags"] # No single critical flag, but composite is high

    print("\nAll core/risk_engine.py self-tests passed!")

if __name__ == "__main__":
    asyncio.run(main())
