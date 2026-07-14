from typing import List, Dict
from config import PAYMENT_CHAIN_MAX_HOPS
from datetime import datetime, timedelta # Import timedelta
import asyncio # Import asyncio

async def validate_payment_chain(payment_chain: List[Dict],
                           original_task: str,
                           authorized_budget_usd: float) -> Dict:
    """
    Validates a cross-agent payment chain against predefined rules.

    Args:
        payment_chain (List[Dict]): A list of payment hop dictionaries.
                                    Each hop: {"agent_id": str, "task": str, "amount_usd": float, "timestamp": datetime}
        original_task (str): The description of the original task.
        authorized_budget_usd (float): The total budget authorized for the entire chain in USD.

    Returns:
        Dict: A dictionary containing validation results, risk, and flags.
    """
    flags = []
    valid = True
    risk = "NONE"

    chain_length = len(payment_chain)
    total_spent_usd = sum(hop.get("amount_usd", 0.0) for hop in payment_chain)
    budget_remaining_usd = authorized_budget_usd - total_spent_usd

    # Check chain length
    if chain_length > PAYMENT_CHAIN_MAX_HOPS:
        valid = False
        risk = "CRITICAL"
        flags.append(f"CRITICAL: Payment chain length ({chain_length}) exceeds maximum authorized hops ({PAYMENT_CHAIN_MAX_HOPS}).")
    elif chain_length > PAYMENT_CHAIN_MAX_HOPS - 1: # Warn if approaching limit
        flags.append(f"WARNING: Payment chain length ({chain_length}) is approaching maximum authorized hops ({PAYMENT_CHAIN_MAX_HOPS}).")

    # Check total spent against budget
    if total_spent_usd > authorized_budget_usd * 1.1: # 10% buffer for minor fluctuations
        valid = False
        risk = "CRITICAL"
        flags.append(f"CRITICAL: Total spent (${total_spent_usd:.2f} USD) critically exceeds authorized budget (${authorized_budget_usd:.2f} USD).")
    elif total_spent_usd > authorized_budget_usd:
        valid = False
        risk = "WARNING"
        flags.append(f"WARNING: Total spent (${total_spent_usd:.2f} USD) exceeds authorized budget (${authorized_budget_usd:.2f} USD).")
    elif total_spent_usd > authorized_budget_usd * 0.9: # Warn if approaching budget limit
        flags.append(f"WARNING: Total spent (${total_spent_usd:.2f} USD) is approaching authorized budget (${authorized_budget_usd:.2f} USD).")

    if not valid and risk == "NONE": # If valid became False but risk wasn't set to CRITICAL, set to WARNING
        risk = "WARNING"
    elif valid and not flags:
        risk = "SAFE"

    return {
        "valid": valid,
        "risk": risk,
        "chain_length": chain_length,
        "total_spent_usd": float(total_spent_usd),
        "budget_remaining_usd": float(budget_remaining_usd),
        "flag": ", ".join(flags) if flags else "Payment chain is valid.",
        "method": "chain_validation"
    }

async def register_payment_hop(payment_chain: List[Dict],
                         agent_id: str,
                         task_description: str,
                         amount_usd: float) -> List[Dict]:
    """
    Appends a new payment hop to the payment chain with a timestamp.

    Args:
        payment_chain (List[Dict]): The current list of payment hop dictionaries.
        agent_id (str): The ID of the agent making the payment.
        task_description (str): A description of the task for this hop.
        amount_usd (float): The amount spent in USD for this hop.

    Returns:
        List[Dict]: The updated payment chain.
    """
    new_hop = {
        "agent_id": agent_id,
        "task": task_description,
        "amount_usd": amount_usd,
        "timestamp": datetime.now()
    }
    payment_chain.append(new_hop)
    return payment_chain

# Self-test block
async def run_self_test():
    print("Running core/chain_validator.py self-test...")

    # Test 1: Valid chain, within limits
    print("\n--- Test 1: Valid chain ---")
    chain_1 = [
        {"agent_id": "agent_A", "task": "subtask1", "amount_usd": 10.0, "timestamp": datetime.now()},
        {"agent_id": "agent_B", "task": "subtask2", "amount_usd": 15.0, "timestamp": datetime.now()},
    ]
    validation_1 = await validate_payment_chain(chain_1, "main_task", 100.0)
    print(f"Validation 1: {validation_1}")
    assert validation_1["valid"] is True
    assert validation_1["risk"] == "SAFE"
    assert validation_1["chain_length"] == 2
    assert validation_1["total_spent_usd"] == 25.0

    # Test 2: Chain length exceeds max hops (CRITICAL)
    print("\n--- Test 2: Chain length critical ---")
    # Assuming PAYMENT_CHAIN_MAX_HOPS is 3 from config
    chain_2 = [
        {"agent_id": "agent_A", "task": "subtask1", "amount_usd": 10.0, "timestamp": datetime.now()},
        {"agent_id": "agent_B", "task": "subtask2", "amount_usd": 15.0, "timestamp": datetime.now()},
        {"agent_id": "agent_C", "task": "subtask3", "amount_usd": 20.0, "timestamp": datetime.now()},
        {"agent_id": "agent_D", "task": "subtask4", "amount_usd": 5.0, "timestamp": datetime.now()},
    ]
    validation_2 = await validate_payment_chain(chain_2, "main_task", 100.0)
    print(f"Validation 2: {validation_2}")
    assert validation_2["valid"] is False
    assert validation_2["risk"] == "CRITICAL"
    assert "exceeds maximum authorized hops" in validation_2["flag"]

    # Test 3: Budget overrun - Critical
    print("\n--- Test 3: Budget critical ---")
    chain_3 = [
        {"agent_id": "agent_A", "task": "subtask1", "amount_usd": 50.0, "timestamp": datetime.now()},
        {"agent_id": "agent_B", "task": "subtask2", "amount_usd": 65.0, "timestamp": datetime.now()},
    ]
    validation_3 = await validate_payment_chain(chain_3, "main_task", 100.0)
    print(f"Validation 3: {validation_3}")
    assert validation_3["valid"] is False
    assert validation_3["risk"] == "CRITICAL"
    assert "critically exceeds authorized budget" in validation_3["flag"]

    # Test 4: Budget overrun - Warning (within 10% buffer)
    print("\n--- Test 4: Budget warning ---")
    chain_4 = [
        {"agent_id": "agent_A", "task": "subtask1", "amount_usd": 50.0, "timestamp": datetime.now()},
        {"agent_id": "agent_B", "task": "subtask2", "amount_usd": 55.0, "timestamp": datetime.now()},
    ]
    validation_4 = await validate_payment_chain(chain_4, "main_task", 100.0)
    print(f"Validation 4: {validation_4}")
    assert validation_4["valid"] is False
    assert validation_4["risk"] == "WARNING"
    assert "exceeds authorized budget" in validation_4["flag"]
    assert "critically" not in validation_4["flag"]

    # Test 5: Approaching max hops (WARNING)
    print("\n--- Test 5: Approaching max hops warning ---")
    chain_5 = [
        {"agent_id": "agent_A", "task": "subtask1", "amount_usd": 10.0, "timestamp": datetime.now()},
        {"agent_id": "agent_B", "task": "subtask2", "amount_usd": 15.0, "timestamp": datetime.now()},
        {"agent_id": "agent_C", "task": "subtask3", "amount_usd": 20.0, "timestamp": datetime.now()},
    ]
    validation_5 = await validate_payment_chain(chain_5, "main_task", 100.0)
    print(f"Validation 5: {validation_5}")
    assert validation_5["valid"] is True
    assert validation_5["risk"] == "SAFE"
    assert "approaching maximum authorized hops" in validation_5["flag"]

    # Test 6: Register payment hop
    print("\n--- Test 6: Register payment hop ---")
    initial_chain = []
    updated_chain = await register_payment_hop(initial_chain, "agent_X", "new_task", 25.0)
    print(f"Updated chain: {updated_chain}")
    assert len(updated_chain) == 1
    assert updated_chain[0]["agent_id"] == "agent_X"
    assert updated_chain[0]["amount_usd"] == 25.0

    print("\nAll core/chain_validator.py self-tests passed!")

if __name__ == "__main__":
    asyncio.run(run_self_test())
