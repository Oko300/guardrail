import numpy as np
from datetime import datetime, timedelta
from collections import Counter
from typing import Dict, List, Optional

from config import O2P_THRESHOLDS, BACKRUN_THRESHOLDS, API_EXHAUSTION_THRESHOLD

async def detect_o2p_pattern(approvals: List[Dict]) -> Dict:
    """
    Detects Overhang-to-Position (O2P) attack patterns from a list of approval events.

    O2P attacks involve multiple individually-safe approvals building toward critical exposure.

    Args:
        approvals (List[Dict]): A list of approval events.
                                Each event should contain:
                                - "contract_address": str
                                - "factory_address": str or None
                                - "amount": float (USD equivalent)
                                - "timestamp": datetime

    Returns:
        Dict: A dictionary containing the O2P score, flags, and overall flag.
    """
    flags = []
    total_approvals = len(approvals)
    total_exposed_usd = sum(app.get("amount", 0.0) for app in approvals)

    # a) Total approval count
    if total_approvals >= O2P_THRESHOLDS["approval_count_critical"]:
        flags.append(f"CRITICAL: High approval count ({total_approvals}) detected.")
    elif total_approvals >= O2P_THRESHOLDS["approval_count_warning"]:
        flags.append(f"WARNING: Elevated approval count ({total_approvals}) detected.")

    # b) Total exposed amount USD
    if total_exposed_usd >= O2P_THRESHOLDS["exposure_critical_usd"]:
        flags.append(f"CRITICAL: Total exposed amount (${total_exposed_usd:.2f} USD) is critically high.")
    elif total_exposed_usd >= O2P_THRESHOLDS["exposure_warning_usd"]:
        flags.append(f"WARNING: Total exposed amount (${total_exposed_usd:.2f} USD) is elevated.")

    # c) Factory clustering
    factory_addresses = [app["factory_address"] for app in approvals if app.get("factory_address")]
    max_factory_cluster = 0
    if factory_addresses:
        factory_counts = Counter(factory_addresses)
        if factory_counts:
            max_factory_cluster = max(factory_counts.values())
    
    if max_factory_cluster >= O2P_THRESHOLDS["same_factory_critical"]:
        flags.append(f"CRITICAL: High factory clustering ({max_factory_cluster} approvals from same factory).")
    elif max_factory_cluster >= O2P_THRESHOLDS["same_factory_warning"]:
        flags.append(f"WARNING: Elevated factory clustering ({max_factory_cluster} approvals from same factory).")

    # d) Recent approvals
    time_window_start = datetime.now() - timedelta(hours=O2P_THRESHOLDS["time_window_hours"])
    recent_approvals = [app for app in approvals if app["timestamp"] >= time_window_start]
    approvals_per_hour = len(recent_approvals) / O2P_THRESHOLDS["time_window_hours"] if O2P_THRESHOLDS["time_window_hours"] > 0 else len(recent_approvals)

    # O2P Score calculation
    o2p_score = min(100.0, (
        max_factory_cluster * 15 +
        (total_exposed_usd / 100) +
        len(recent_approvals) * 8
    ))

    overall_flag = "CLEAN"
    if o2p_score > 60:
        overall_flag = "CRITICAL_O2P"
    elif o2p_score > 25:
        overall_flag = "ACCUMULATING"

    return {
        "o2p_score": float(o2p_score),
        "total_approvals": total_approvals,
        "total_exposed_usd": float(total_exposed_usd),
        "max_factory_cluster": max_factory_cluster,
        "approvals_per_hour": float(approvals_per_hour),
        "flags": flags,
        "overall_flag": overall_flag,
        "method": "o2p_pattern_detection"
    }

async def detect_backrun_risk(amount_usd: float, pool_liquidity_usd: float, token_in: str, token_out: str) -> Dict:
    """
    Detects potential backrun risk based on trade amount and pool liquidity.

    Args:
        amount_usd (float): The USD value of the trade.
        pool_liquidity_usd (float): The total liquidity of the pool in USD.
        token_in (str): The address of the token being traded in.
        token_out (str): The address of the token being traded out.

    Returns:
        Dict: A dictionary containing the backrun risk level, liquidity ratio, and flag.
    """
    if pool_liquidity_usd == 0.0 or pool_liquidity_usd < BACKRUN_THRESHOLDS["min_pool_liquidity_usd"]:
        risk = "UNKNOWN"
        flag = "Insufficient pool liquidity data or below minimum threshold for analysis."
        liquidity_ratio = 0.0
    else:
        liquidity_ratio = amount_usd / pool_liquidity_usd
        if liquidity_ratio >= BACKRUN_THRESHOLDS["pool_liquidity_ratio_critical"]:
            risk = "CRITICAL"
            flag = "CRITICAL: Trade amount is a very high percentage of pool liquidity, indicating high backrun risk."
        elif liquidity_ratio >= BACKRUN_THRESHOLDS["pool_liquidity_ratio_warning"]:
            risk = "HIGH"
            flag = "WARNING: Trade amount is a high percentage of pool liquidity, indicating elevated backrun risk."
        elif pool_liquidity_usd < BACKRUN_THRESHOLDS["min_pool_liquidity_usd"]:
            risk = "MEDIUM"
            flag = "WARNING: Pool liquidity is below minimum threshold, increasing backrun risk."
        else:
            risk = "LOW"
            flag = "LOW: Trade amount is a small percentage of pool liquidity, low backrun risk."

    return {
        "backrun_risk": risk,
        "liquidity_ratio": float(liquidity_ratio),
        "pool_liquidity_usd": float(pool_liquidity_usd),
        "trade_amount_usd": float(amount_usd),
        "flag": flag,
        "method": "backrun_risk_detection"
    }

async def detect_api_exhaustion(security_failures: int, session_age_hours: float) -> Dict:
    """
    Detects potential API exhaustion attacks.

    Args:
        security_failures (int): The number of security API failures recorded for the session.
        session_age_hours (float): The age of the session in hours.

    Returns:
        Dict: A dictionary containing the risk level, failure count, failure rate, and flag.
    """
    risk = "NONE"
    flag = "No API exhaustion risk detected."
    failure_rate_per_hour = security_failures / session_age_hours if session_age_hours > 0 else 0.0

    if security_failures >= API_EXHAUSTION_THRESHOLD:
        risk = "CRITICAL"
        flag = f"CRITICAL: Security API exhaustion detected with {security_failures} failures."
    elif security_failures >= 2:
        risk = "WARNING"
        flag = f"WARNING: Elevated security API failures ({security_failures}) detected, potential exhaustion attempt."
    elif security_failures == 1:
        risk = "LOW"
        flag = "LOW: One security API failure detected, monitoring for further issues."

    return {
        "risk": risk,
        "failure_count": security_failures,
        "failure_rate_per_hour": float(failure_rate_per_hour),
        "flag": flag,
        "method": "api_exhaustion_detection"
    }

async def detect_skill_infection(skills_called: List[Dict]) -> Dict:
    """
    Detects potential skill infection based on behavioral changes after skill calls.

    Args:
        skills_called (List[Dict]): A list of skill call records.
                                    Each record should contain:
                                    - "skill_id": str
                                    - "behavior_changed": bool
                                    - "timestamp": datetime

    Returns:
        Dict: A dictionary containing the risk level, infected skills, and flag.
    """
    infected_skills = [s["skill_id"] for s in skills_called if s.get("behavior_changed")]
    
    risk = "NONE"
    flag = "No skill infection detected."
    if infected_skills:
        risk = "CRITICAL"
        flag = f"CRITICAL: Agent behavior changed after calling skill(s): {', '.join(infected_skills)}. Potential skill infection."

    return {
        "risk": risk,
        "infected_skills": infected_skills,
        "flag": flag,
        "method": "skill_infection_detection"
    }

import asyncio # Import asyncio

# Self-test block
async def main():
    print("Running core/patterns.py self-test...")

    now = datetime.now()

    # Test 1: O2P Pattern Detection - CLEAN
    print("\n--- Test 1: O2P Pattern Detection - CLEAN ---")
    approvals_clean = [
        {"contract_address": "0x1", "factory_address": "0xfac1", "token": "USDT", "amount": 10.0, "timestamp": now - timedelta(hours=5)},
        {"contract_address": "0x2", "factory_address": "0xfac2", "token": "ETH", "amount": 20.0, "timestamp": now - timedelta(hours=3)},
    ]
    o2p_clean = await detect_o2p_pattern(approvals_clean)
    print(f"O2P Clean: {o2p_clean}")
    assert o2p_clean["overall_flag"] == "CLEAN"
    assert o2p_clean["o2p_score"] < 25

    # Test 2: O2P Pattern Detection - ACCUMULATING (warning count, exposure)
    print("\n--- Test 2: O2P Pattern Detection - ACCUMULATING ---")
    approvals_accumulating = [
        {"contract_address": "0x1", "factory_address": "0xfac1", "token": "USDT", "amount": 200.0, "timestamp": now - timedelta(minutes=50)},
        {"contract_address": "0x2", "factory_address": "0xfac2", "token": "ETH", "amount": 300.0, "timestamp": now - timedelta(minutes=40)},
        {"contract_address": "0x3", "factory_address": "0xfac1", "token": "DAI", "amount": 400.0, "timestamp": now - timedelta(minutes=30)},
        {"contract_address": "0x4", "factory_address": "0xfac3", "token": "USDC", "amount": 500.0, "timestamp": now - timedelta(minutes=20)},
        {"contract_address": "0x5", "factory_address": "0xfac1", "token": "WBTC", "amount": 600.0, "timestamp": now - timedelta(minutes=10)},
    ]
    o2p_accumulating = await detect_o2p_pattern(approvals_accumulating)
    print(f"O2P Accumulating: {o2p_accumulating}")
    assert o2p_accumulating["overall_flag"] == "ACCUMULATING"
    assert any("approval count" in flag for flag in o2p_accumulating["flags"])
    assert any("exposed amount" in flag for flag in o2p_accumulating["flags"])
    assert o2p_accumulating["o2p_score"] >= 25 and o2p_accumulating["o2p_score"] < 60

    # Test 3: O2P Pattern Detection - CRITICAL (high count, high exposure, high clustering)
    print("\n--- Test 3: O2P Pattern Detection - CRITICAL ---")
    approvals_critical = [
        {"contract_address": "0x1", "factory_address": "0xfac1", "token": "USDT", "amount": 1000.0, "timestamp": now - timedelta(minutes=50)},
        {"contract_address": "0x2", "factory_address": "0xfac1", "token": "ETH", "amount": 1500.0, "timestamp": now - timedelta(minutes=40)},
        {"contract_address": "0x3", "factory_address": "0xfac1", "token": "DAI", "amount": 2000.0, "timestamp": now - timedelta(minutes=30)},
        {"contract_address": "0x4", "factory_address": "0xfac1", "token": "USDC", "amount": 2500.0, "timestamp": now - timedelta(minutes=20)},
        {"contract_address": "0x5", "factory_address": "0xfac1", "token": "WBTC", "amount": 3000.0, "timestamp": now - timedelta(minutes=10)},
        {"contract_address": "0x6", "factory_address": "0xfac1", "token": "LINK", "amount": 3500.0, "timestamp": now - timedelta(minutes=5)},
        {"contract_address": "0x7", "factory_address": "0xfac2", "token": "UNI", "amount": 100.0, "timestamp": now - timedelta(minutes=2)},
    ]
    o2p_critical = await detect_o2p_pattern(approvals_critical)
    print(f"O2P Critical: {o2p_critical}")
    assert o2p_critical["overall_flag"] == "CRITICAL_O2P"
    assert any("CRITICAL" in flag for flag in o2p_critical["flags"])
    assert o2p_critical["o2p_score"] >= 60

    # Test 4: Backrun Risk - LOW
    print("\n--- Test 4: Backrun Risk - LOW ---")
    backrun_low = await detect_backrun_risk(amount_usd=1000.0, pool_liquidity_usd=1000000.0, token_in="0xabc", token_out="0xdef")
    print(f"Backrun Low: {backrun_low}")
    assert backrun_low["backrun_risk"] == "LOW"

    # Test 5: Backrun Risk - HIGH
    print("\n--- Test 5: Backrun Risk - HIGH ---")
    backrun_high = await detect_backrun_risk(amount_usd=50000.0, pool_liquidity_usd=200000.0, token_in="0xabc", token_out="0xdef")
    print(f"Backrun High: {backrun_high}")
    assert backrun_high["backrun_risk"] == "HIGH"
    assert "elevated backrun risk" in backrun_high["flag"]

    # Test 6: Backrun Risk - CRITICAL
    print("\n--- Test 6: Backrun Risk - CRITICAL ---")
    backrun_critical = await detect_backrun_risk(amount_usd=50000.0, pool_liquidity_usd=100000.0, token_in="0xabc", token_out="0xdef")
    print(f"Backrun Critical: {backrun_critical}")
    assert backrun_critical["backrun_risk"] == "CRITICAL"
    assert "high backrun risk" in backrun_critical["flag"]

    # Test 7: Backrun Risk - UNKNOWN (low liquidity)
    print("\n--- Test 7: Backrun Risk - UNKNOWN (low liquidity) ---")
    backrun_unknown = await detect_backrun_risk(amount_usd=100.0, pool_liquidity_usd=50000.0, token_in="0xabc", token_out="0xdef")
    print(f"Backrun Unknown: {backrun_unknown}")
    assert backrun_unknown["backrun_risk"] == "MEDIUM" # Changed from UNKNOWN to MEDIUM based on task description
    assert "below minimum threshold" in backrun_unknown["flag"]

    # Test 8: API Exhaustion - NONE
    print("\n--- Test 8: API Exhaustion - NONE ---")
    api_exhaustion_none = await detect_api_exhaustion(security_failures=0, session_age_hours=1.0)
    print(f"API Exhaustion None: {api_exhaustion_none}")
    assert api_exhaustion_none["risk"] == "NONE"

    # Test 9: API Exhaustion - WARNING
    print("\n--- Test 9: API Exhaustion - WARNING ---")
    api_exhaustion_warning = await detect_api_exhaustion(security_failures=2, session_age_hours=1.0)
    print(f"API Exhaustion Warning: {api_exhaustion_warning}")
    assert api_exhaustion_warning["risk"] == "WARNING"

    # Test 10: API Exhaustion - CRITICAL
    print("\n--- Test 10: API Exhaustion - CRITICAL ---")
    api_exhaustion_critical = await detect_api_exhaustion(security_failures=API_EXHAUSTION_THRESHOLD, session_age_hours=1.0)
    print(f"API Exhaustion Critical: {api_exhaustion_critical}")
    assert api_exhaustion_critical["risk"] == "CRITICAL"

    # Test 11: Skill Infection - NONE
    print("\n--- Test 11: Skill Infection - NONE ---")
    skills_clean = [
        {"skill_id": "skill_a", "behavior_changed": False, "timestamp": now},
        {"skill_id": "skill_b", "behavior_changed": False, "timestamp": now},
    ]
    skill_infection_none = await detect_skill_infection(skills_clean)
    print(f"Skill Infection None: {skill_infection_none}")
    assert skill_infection_none["risk"] == "NONE"

    # Test 12: Skill Infection - CRITICAL
    print("\n--- Test 12: Skill Infection - CRITICAL ---")
    skills_infected = [
        {"skill_id": "skill_a", "behavior_changed": False, "timestamp": now},
        {"skill_id": "skill_b", "behavior_changed": True, "timestamp": now},
    ]
    skill_infection_critical = await detect_skill_infection(skills_infected)
    print(f"Skill Infection Critical: {skill_infection_critical}")
    assert skill_infection_critical["risk"] == "CRITICAL"
    assert "skill_b" in skill_infection_critical["infected_skills"]

    print("\nAll core/patterns.py self-tests passed!")

if __name__ == "__main__":
    asyncio.run(main())
