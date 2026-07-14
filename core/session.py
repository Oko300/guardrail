import uuid
from datetime import datetime, timedelta
import uuid
import asyncio # Import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from config import SESSION_TIMEOUT_HOURS
from core.baseline import build_baseline

# In-memory storage for sessions
sessions: Dict[str, Dict] = {}

async def create_session(agent_id: str, initial_budget_usd: float = 0.0, authorized_chain_hops: int = 3, task_description: str = "") -> Dict:
    """
    Generates a new session for an AI agent.

    Args:
        agent_id (str): The ID of the AI agent.
        initial_budget_usd (float): The initial budget authorized for the agent in USD.
        authorized_chain_hops (int): The maximum number of payment chain hops authorized.
        task_description (str): A description of the task the agent is performing.

    Returns:
        Dict: The newly created session dictionary.
    """
    session_id = str(uuid.uuid4())
    now = datetime.now()
    session = {
        "session_id": session_id,
        "agent_id": agent_id,
        "created_at": now,
        "last_active": now,
        "transactions": [],
        "approvals": [],
        "security_api_failures": 0,
        "payment_chain": [],
        "baseline": {"established": False},
        "risk_score_history": [],
        "skills_called": [],
        "status": "active",  # "active", "suspended", "flagged"
        "initial_budget_usd": initial_budget_usd,
        "authorized_chain_hops": authorized_chain_hops,
        "task_description": task_description,
    }
    sessions[session_id] = session
    return session

async def get_session(session_id: str) -> Optional[Dict]:
    """
    Retrieves a session by its ID.

    Args:
        session_id (str): The UUID of the session.

    Returns:
        Optional[Dict]: The session dictionary if found, otherwise None.
    """
    return sessions.get(session_id)

async def add_transaction(session_id: str, tx_record: Dict) -> bool:
    """
    Adds a transaction record to an existing session.

    Args:
        session_id (str): The UUID of the session.
        tx_record (Dict): The transaction record to add.
                          Expected keys: tx_hash, token_in, token_out, amount_usd,
                          contract_address, timestamp, individual_verdict,
                          session_risk_score, gas_price, pool_liquidity_usd.

    Returns:
        bool: True if the transaction was added successfully, False otherwise.
    """
    session = await get_session(session_id)
    if not session:
        return False

    session["transactions"].append(tx_record)
    session["last_active"] = datetime.now()
    session["risk_score_history"].append(tx_record["session_risk_score"])

    # Rebuild baseline if 3 or more transactions exist
    if len(session["transactions"]) >= 3:
        session["baseline"] = await build_baseline(session["transactions"])

    return True

async def add_approval(session_id: str, approval: Dict) -> bool:
    """
    Adds an approval event to an existing session.

    Args:
        session_id (str): The UUID of the session.
        approval (Dict): The approval event to add.
                          Expected keys: contract_address, factory_address,
                          token, amount, timestamp.

    Returns:
        bool: True if the approval was added successfully, False otherwise.
    """
    session = await get_session(session_id)
    if not session:
        return False

    session["approvals"].append(approval)
    session["last_active"] = datetime.now()
    return True

async def record_security_failure(session_id: str):
    """
    Increments the security API failure counter for a session.

    Args:
        session_id (str): The UUID of the session.
    """
    session = await get_session(session_id)
    if session:
        session["security_api_failures"] += 1
        session["last_active"] = datetime.now()

async def add_payment_hop(session_id: str, hop: Dict) -> bool:
    """
    Adds a payment chain hop to an existing session.

    Args:
        session_id (str): The UUID of the session.
        hop (Dict): The payment hop to add.
                    Expected keys: agent_id, task, amount_usd.

    Returns:
        bool: True if the hop was added successfully, False otherwise.
    """
    session = await get_session(session_id)
    if not session:
        return False

    session["payment_chain"].append(hop)
    session["last_active"] = datetime.now()
    return True

async def add_skill_call(session_id: str, skill_id: str, behavior_changed: bool):
    """
    Tracks a skill call for a session and flags potential skill infection.

    Args:
        session_id (str): The UUID of the session.
        skill_id (str): The ID of the skill (ASP) called.
        behavior_changed (bool): True if agent behavior changed after this skill call.
    """
    session = await get_session(session_id)
    if session:
        session["skills_called"].append({"skill_id": skill_id, "behavior_changed": behavior_changed, "timestamp": datetime.now()})
        session["last_active"] = datetime.now()
        if behavior_changed:
            session["status"] = "flagged" # Flag for potential skill infection

async def suspend_session(session_id: str, reason: str):
    """
    Suspends a session and logs the reason.

    Args:
        session_id (str): The UUID of the session.
        reason (str): The reason for suspension.
    """
    session = await get_session(session_id)
    if session:
        session["status"] = "suspended"
        session["suspension_reason"] = reason
        session["last_active"] = datetime.now()

async def cleanup_expired_sessions():
    """
    Removes sessions that are older than SESSION_TIMEOUT_HOURS.
    """
    now = datetime.now()
    expired_session_ids = [
        session_id for session_id, session in sessions.items()
        if (now - session["last_active"]) > timedelta(hours=SESSION_TIMEOUT_HOURS)
    ]
    for session_id in expired_session_ids:
        await delete_session(session_id) # Use the new async delete_session

async def get_session_stats() -> Dict:
    """
    Returns statistics about the current sessions.

    Returns:
        Dict: A dictionary containing total, active, suspended, and flagged session counts.
    """
    total = len(sessions)
    active = sum(1 for s in sessions.values() if s["status"] == "active")
    suspended = sum(1 for s in sessions.values() if s["status"] == "suspended")
    flagged = sum(1 for s in sessions.values() if s["status"] == "flagged")
    return {
        "total_sessions": total,
        "active_sessions": active,
        "suspended_sessions": suspended,
        "flagged_sessions": flagged,
    }

async def delete_session(session_id: str) -> bool:
    """
    Deletes a session from memory.

    Args:
        session_id (str): The UUID of the session to delete.

    Returns:
        bool: True if the session was deleted, False if not found.
    """
    if session_id in sessions:
        del sessions[session_id]
        return True
    return False
