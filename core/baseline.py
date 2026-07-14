import numpy as np
from datetime import datetime, timedelta
from collections import Counter
from typing import Dict, List, Tuple
import asyncio # Import asyncio

from config import DRIFT_THRESHOLDS

async def build_baseline(transactions: List[Dict]) -> Dict:
    """
    Establishes a behavioral baseline for an agent based on its transaction history.

    Requires a minimum of 3 transactions to establish a baseline.

    Args:
        transactions (List[Dict]): A list of transaction records.
                                   Each record should contain:
                                   - "amount_usd": float
                                   - "timestamp": datetime
                                   - "contract_address": str
                                   - "gas_price": int or None
                                   - "session_risk_score": float

    Returns:
        Dict: A dictionary representing the established baseline, or {"established": False}
              if insufficient data.
    """
    if len(transactions) < 3:
        return {"established": False}

    amounts = [tx["amount_usd"] for tx in transactions]
    timestamps = [tx["timestamp"] for tx in transactions]
    contract_addresses = [tx["contract_address"] for tx in transactions]
    gas_prices = [tx["gas_price"] for tx in transactions if tx["gas_price"] is not None]
    session_risk_scores = [tx["session_risk_score"] for tx in transactions]

    # Calculate mean and std deviation of amount_usd
    mean_amount_usd = np.mean(amounts)
    std_amount_usd = np.std(amounts, ddof=1) if len(amounts) > 1 else 0.0

    # Calculate mean frequency per hour
    min_timestamp = min(timestamps)
    max_timestamp = max(timestamps)
    hours_elapsed = (max_timestamp - min_timestamp).total_seconds() / 3600
    mean_frequency_per_hour = len(transactions) / hours_elapsed if hours_elapsed > 0 else 0.0

    # Identify typical contract types (most common 6-char prefixes)
    contract_prefixes = [addr[:6] for addr in contract_addresses]
    typical_contract_types = [item for item, count in Counter(contract_prefixes).most_common(3)] # Top 3 most common

    # Typical gas range
    typical_gas_range = (min(gas_prices), max(gas_prices)) if gas_prices else (None, None)

    # Active hours
    active_hours = sorted(list(set(t.hour for t in timestamps)))

    # Average session risk score
    avg_session_risk_score = np.mean(session_risk_scores)

    return {
        "established": True,
        "mean_amount_usd": float(mean_amount_usd),
        "std_amount_usd": float(std_amount_usd),
        "mean_frequency_per_hour": float(mean_frequency_per_hour),
        "typical_contract_types": typical_contract_types,
        "typical_gas_range": typical_gas_range,
        "active_hours": active_hours,
        "avg_session_risk_score": float(avg_session_risk_score),
        "sample_size": len(transactions),
        "established_at": datetime.now().isoformat()
    }

async def calculate_drift(baseline: Dict, recent_transactions: List[Dict], current_tx: Dict) -> Dict:
    """
    Calculates behavioral drift for a current transaction against an established baseline.

    Args:
        baseline (Dict): The established behavioral baseline.
        recent_transactions (List[Dict]): A list of recent transaction records (e.g., last hour).
        current_tx (Dict): The current transaction record.

    Returns:
        Dict: A dictionary containing the drift score, flags, and overall flag.
    """
    if not baseline.get("established"):
        return {
            "drift_score": 0.0,
            "z_amount": 0.0,
            "frequency_ratio": 0.0,
            "frequency_flag": "Insufficient data to establish baseline.",
            "contract_flag": "Insufficient data to establish baseline.",
            "time_flag": "Insufficient data to establish baseline.",
            "drift_velocity": 0.0,
            "flags": ["INFO: Insufficient data to establish baseline."],
            "overall_flag": "NORMAL",
            "method": "behavioral_drift_detection"
        }

    flags = []

    # a) Amount Deviation (Z-score)
    z_amount = abs(current_tx["amount_usd"] - baseline["mean_amount_usd"]) / max(baseline["std_amount_usd"], 1e-6) # Avoid division by zero
    if z_amount > DRIFT_THRESHOLDS["size_deviation_critical"]:
        flags.append(f"CRITICAL: Transaction amount (Z-score: {z_amount:.2f}) critically deviates from baseline.")
    elif z_amount > DRIFT_THRESHOLDS["size_deviation_warning"]:
        flags.append(f"WARNING: Transaction amount (Z-score: {z_amount:.2f}) significantly deviates from baseline.")

    # b) Frequency Drift
    recent_frequency = len(recent_transactions) / 1.0 # Assuming recent_transactions are from the last hour
    frequency_ratio = recent_frequency / max(baseline["mean_frequency_per_hour"], 0.1) # Avoid division by zero
    frequency_flag = "Normal transaction frequency."
    if frequency_ratio > DRIFT_THRESHOLDS["frequency_deviation_critical"]:
        frequency_flag = f"CRITICAL: Transaction frequency ({recent_frequency:.2f}/hr) critically higher than baseline ({baseline['mean_frequency_per_hour']:.2f}/hr)."
        flags.append(frequency_flag)
    elif frequency_ratio > DRIFT_THRESHOLDS["frequency_deviation_warning"]:
        frequency_flag = f"WARNING: Transaction frequency ({recent_frequency:.2f}/hr) significantly higher than baseline ({baseline['mean_frequency_per_hour']:.2f}/hr)."
        flags.append(frequency_flag)
    elif frequency_ratio < 1.0 / DRIFT_THRESHOLDS["frequency_deviation_critical"]: # Significantly lower frequency
        frequency_flag = f"WARNING: Transaction frequency ({recent_frequency:.2f}/hr) significantly lower than baseline ({baseline['mean_frequency_per_hour']:.2f}/hr)."
        flags.append(frequency_flag)


    # c) Contract Type Deviation
    current_contract_prefix = current_tx["contract_address"][:6]
    is_known_contract_type = current_contract_prefix in baseline["typical_contract_types"]
    contract_flag = "Contract type is typical for this agent."
    if not is_known_contract_type:
        contract_flag = f"WARNING: Contract type ({current_contract_prefix}) is atypical for this agent."
        flags.append(contract_flag)

    # d) Time-of-Day Deviation
    current_hour = datetime.now().hour
    is_active_hour = current_hour in baseline["active_hours"]
    time_flag = "Transaction within typical active hours."
    if not is_active_hour:
        time_flag = f"WARNING: Transaction initiated outside typical active hours ({current_hour}:00)."
        flags.append(time_flag)

    # e) Drift Velocity
    recent_scores = [tx["session_risk_score"] for tx in recent_transactions[-5:]] # Last 5 session_risk_scores
    drift_velocity = 0.0
    if len(recent_scores) >= 3 and baseline["avg_session_risk_score"] > 0:
        drift_velocity = (np.mean(recent_scores) - baseline["avg_session_risk_score"]) / baseline["avg_session_risk_score"]
    
    if drift_velocity > DRIFT_THRESHOLDS["velocity_critical"]:
        flags.append(f"CRITICAL: Risk score velocity ({drift_velocity:.2f}) critically increasing.")
    elif drift_velocity > DRIFT_THRESHOLDS["velocity_warning"]:
        flags.append(f"WARNING: Risk score velocity ({drift_velocity:.2f}) significantly increasing.")

    # f) Composite Drift Score (0-100)
    drift_score = min(100.0, (
        z_amount * 10 +
        max(0, frequency_ratio - 1) * 20 +
        (30 if not is_known_contract_type else 0) +
        (15 if not is_active_hour else 0) +
        max(0, drift_velocity) * 25 # Only positive drift velocity contributes to score
    ))

    overall_flag = "NORMAL"
    if drift_score > 60:
        overall_flag = "CRITICAL_DRIFT"
    elif drift_score > 30:
        overall_flag = "DRIFTING"

    return {
        "drift_score": float(drift_score),
        "z_amount": float(z_amount),
        "frequency_ratio": float(frequency_ratio),
        "frequency_flag": frequency_flag,
        "contract_flag": contract_flag,
        "time_flag": time_flag,
        "drift_velocity": float(drift_velocity),
        "flags": flags,
        "overall_flag": overall_flag,
        "method": "behavioral_drift_detection"
    }

# Self-test block
async def main():
    print("Running core/baseline.py self-test...")

    now = datetime.now()

    # Sample transactions for baseline
    sample_transactions = [
        {"amount_usd": 100.0, "timestamp": now - timedelta(hours=5), "contract_address": "0xabcdef123456", "gas_price": 20, "session_risk_score": 10.0},
        {"amount_usd": 120.0, "timestamp": now - timedelta(hours=4), "contract_address": "0xabcdef123456", "gas_price": 22, "session_risk_score": 12.0},
        {"amount_usd": 110.0, "timestamp": now - timedelta(hours=3), "contract_address": "0x123456abcdef", "gas_price": 21, "session_risk_score": 11.0},
        {"amount_usd": 130.0, "timestamp": now - timedelta(hours=2), "contract_address": "0xabcdef123456", "gas_price": 25, "session_risk_score": 15.0},
        {"amount_usd": 105.0, "timestamp": now - timedelta(hours=1), "contract_address": "0x123456abcdef", "gas_price": 23, "session_risk_score": 13.0},
    ]

    # Test 1: Build Baseline - Insufficient data
    print("\n--- Test 1: Build Baseline - Insufficient data ---")
    baseline_insufficient = await build_baseline(sample_transactions[:2])
    print(f"Baseline Insufficient: {baseline_insufficient}")
    assert not baseline_insufficient["established"]

    # Test 2: Build Baseline - Sufficient data
    print("\n--- Test 2: Build Baseline - Sufficient data ---")
    baseline_established = await build_baseline(sample_transactions)
    print(f"Baseline Established: {baseline_established}")
    assert baseline_established["established"]
    assert baseline_established["sample_size"] == 5
    assert "mean_amount_usd" in baseline_established
    assert "typical_contract_types" in baseline_established

    # Test 3: Calculate Drift - Insufficient baseline
    print("\n--- Test 3: Calculate Drift - Insufficient baseline ---")
    current_tx_1 = {"amount_usd": 150.0, "timestamp": now, "contract_address": "0xnewcontract", "gas_price": 30, "session_risk_score": 20.0}
    drift_insufficient = await calculate_drift(baseline_insufficient, [], current_tx_1)
    print(f"Drift Insufficient: {drift_insufficient}")
    assert drift_insufficient["overall_flag"] == "NORMAL"
    assert "Insufficient data" in drift_insufficient["flags"][0]

    # Test 4: Calculate Drift - Normal transaction
    print("\n--- Test 4: Calculate Drift - Normal transaction ---")
    current_tx_2 = {"amount_usd": 115.0, "timestamp": now, "contract_address": "0xabcdef123456", "gas_price": 22, "session_risk_score": 12.0}
    recent_txs_2 = sample_transactions[-1:] # Last 1 transaction
    drift_normal = await calculate_drift(baseline_established, recent_txs_2, current_tx_2)
    print(f"Drift Normal: {drift_normal}")
    assert drift_normal["overall_flag"] == "NORMAL"
    assert drift_normal["drift_score"] < 30

    # Test 5: Calculate Drift - Amount Deviation Warning
    print("\n--- Test 5: Calculate Drift - Amount Deviation Warning ---")
    current_tx_3 = {"amount_usd": 300.0, "timestamp": now, "contract_address": "0xabcdef123456", "gas_price": 22, "session_risk_score": 12.0}
    drift_amount_warning = await calculate_drift(baseline_established, recent_txs_2, current_tx_3)
    print(f"Drift Amount Warning: {drift_amount_warning}")
    assert drift_amount_warning["overall_flag"] == "DRIFTING"
    assert any("amount" in flag for flag in drift_amount_warning["flags"])

    # Test 6: Calculate Drift - Frequency Drift Warning (high frequency)
    print("\n--- Test 6: Calculate Drift - Frequency Drift Warning (high frequency) ---")
    current_tx_4 = {"amount_usd": 115.0, "timestamp": now, "contract_address": "0xabcdef123456", "gas_price": 22, "session_risk_score": 12.0}
    recent_txs_4 = [current_tx_4] * 4 # Simulate 4 transactions in the last hour
    drift_frequency_warning = await calculate_drift(baseline_established, recent_txs_4, current_tx_4)
    print(f"Drift Frequency Warning: {drift_frequency_warning}")
    assert drift_frequency_warning["overall_flag"] == "DRIFTING"
    assert any("frequency" in flag for flag in drift_frequency_warning["flags"])

    # Test 7: Calculate Drift - Contract Type Deviation Warning
    print("\n--- Test 7: Calculate Drift - Contract Type Deviation Warning ---")
    current_tx_5 = {"amount_usd": 115.0, "timestamp": now, "contract_address": "0xnewcontract", "gas_price": 22, "session_risk_score": 12.0}
    drift_contract_warning = await calculate_drift(baseline_established, recent_txs_2, current_tx_5)
    print(f"Drift Contract Warning: {drift_contract_warning}")
    assert drift_contract_warning["overall_flag"] == "DRIFTING"
    assert any("Contract type" in flag for flag in drift_contract_warning["flags"])

    # Test 8: Calculate Drift - Time-of-Day Deviation Warning (assuming current hour is not active)
    print("\n--- Test 8: Calculate Drift - Time-of-Day Deviation Warning ---")
    # To test this, we need to ensure current_hour is not in baseline_established["active_hours"]
    # For demo purposes, let's assume it's not.
    current_tx_6 = {"amount_usd": 115.0, "timestamp": now.replace(hour=(baseline_established["active_hours"][0] - 1) % 24), "contract_address": "0xabcdef123456", "gas_price": 22, "session_risk_score": 12.0}
    drift_time_warning = await calculate_drift(baseline_established, recent_txs_2, current_tx_6)
    print(f"Drift Time Warning: {drift_time_warning}")
    assert drift_time_warning["overall_flag"] == "DRIFTING"
    assert any("active hours" in flag for flag in drift_time_warning["flags"])

    # Test 9: Calculate Drift - Critical Drift (multiple factors, high score)
    print("\n--- Test 9: Calculate Drift - Critical Drift ---")
    current_tx_7 = {"amount_usd": 500.0, "timestamp": now.replace(hour=(baseline_established["active_hours"][0] - 1) % 24), "contract_address": "0xverynewcontract", "gas_price": 50, "session_risk_score": 80.0}
    recent_txs_7 = [
        {"amount_usd": 100.0, "timestamp": now - timedelta(minutes=4), "contract_address": "0xabcdef123456", "gas_price": 20, "session_risk_score": 60.0},
        {"amount_usd": 120.0, "timestamp": now - timedelta(minutes=3), "contract_address": "0xabcdef123456", "gas_price": 22, "session_risk_score": 70.0},
        {"amount_usd": 110.0, "timestamp": now - timedelta(minutes=2), "contract_address": "0x123456abcdef", "gas_price": 21, "session_risk_score": 80.0},
        {"amount_usd": 130.0, "timestamp": now - timedelta(minutes=1), "contract_address": "0xabcdef123456", "gas_price": 25, "session_risk_score": 90.0},
        current_tx_7 # Current transaction is also recent
    ]
    drift_critical = await calculate_drift(baseline_established, recent_txs_7, current_tx_7)
    print(f"Drift Critical: {drift_critical}")
    assert drift_critical["overall_flag"] == "CRITICAL_DRIFT"
    assert drift_critical["drift_score"] >= 60
    assert any("CRITICAL" in flag for flag in drift_critical["flags"])

    print("\nAll core/baseline.py self-tests passed!")

if __name__ == "__main__":
    asyncio.run(main())
