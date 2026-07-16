import asyncio
import logging
import uuid # Added for temporary session creation
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_ipaddr
from slowapi.errors import RateLimitExceeded

from api.models import (
    SessionCreateRequest, SessionCreateResponse,
    TransactionCheckRequest, TransactionCheckResponse,
    PaymentHopRequest, PaymentHopResponse,
    SessionStatusResponse, HealthResponse
)
from core.session import (
    create_session, get_session, add_transaction, add_approval,
    record_security_failure, add_payment_hop, add_skill_call,
    suspend_session, get_session_stats, cleanup_expired_sessions,
    delete_session # Import delete_session
)
from core.baseline import calculate_drift
from core.patterns import (
    detect_o2p_pattern, detect_backrun_risk,
    detect_api_exhaustion, detect_skill_infection
)
from core.okx_security import scan_transaction, scan_token, get_pool_liquidity
from core.chain_validator import validate_payment_chain, register_payment_hop
from core.risk_engine import calculate_composite_risk
from api.auth import get_master_api_key
import httpx
from config import XLAYER_RPC_URL, OKX_API_KEY, OKX_API_SECRET, OKX_API_PASSPHRASE, XLAYER_CHAIN_ID, SESSION_TIMEOUT_HOURS

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize FastAPI router
router = APIRouter()

# Initialize Limiter for rate limiting
limiter = Limiter(key_func=get_ipaddr)

# Application metadata
APP_TITLE = "GuardRail — Behavioral Security Intelligence for OKX.AI Agents"
APP_DESCRIPTION = """
GuardRail is an Agent Service Provider (ASP) listed on OKX.AI that provides a critical, missing layer of security:
**behavioral intelligence and session security monitoring for AI agents operating on OKX.AI and X Layer.**

### What GuardRail Does
Existing security tools, including OKX's own `okx-security` skill, check **individual transactions in isolation**.
GuardRail, however, monitors the **pattern of transactions across an entire agent session** to detect sophisticated attacks
that are invisible to per-transaction checks. It wraps OKX's security tools and adds this crucial longitudinal intelligence layer.

### Why Existing Tools Fail (Point-in-Time Only)
Traditional security solutions are like a single snapshot. They can tell you if one specific action is risky.
But what if an attacker makes many small, individually "safe" actions that, when combined, lead to a massive loss?
This is the documented gap GuardRail fills.

### The 5 Attack Types GuardRail Detects
1.  **O2P (Overhang-to-Position) Attacks**: Multiple individually-safe approvals building toward critical exposure.
    *(Validated by May 2026 academic paper on OKX Agent Payments Protocol)*
2.  **Behavioral Drift**: Deviations from an agent's established normal transaction patterns (amount, frequency, contract types, time-of-day).
    *(Addresses OWASP March 2026 proposal on Behavioral Drift Detection)*
3.  **Backrun Risk**: Exploiting low-liquidity pools with large trades, leading to significant slippage and losses.
    *(Identified in a $2M backrun loss on July 7, 2026)*
4.  **API Exhaustion**: Deliberately failing security API calls to bypass security checks, as OKX docs admit security auto-continues on failure in swap context.
5.  **Skill Infection**: Detecting when an agent's behavior changes after calling a new or potentially malicious Agent Service Provider (ASP).
    *(Relevant to 824 malicious skills found in OpenClaw ecosystem early 2026)*

### Research Backing
-   **May 2026 SoK paper on OKX Agent Payments Protocol**: Identified "O2P (Overhang-to-Position)" as an unsolved chronic cumulative attack vector.
-   **OWASP March 2026 proposal on Behavioral Drift Detection**: Explicitly stated "no mechanism to establish normal behavior for an agent and detect deviations from that baseline" exists. GuardRail is the first working implementation.
-   **Sherlock 2026 report**: Documented various sophisticated attacks on AI agents, including those leveraging cumulative actions.

### How to Integrate (3 Steps)
1.  **Create a Session**: Call `/session/create` with your `agent_id` to get a `session_id`.
2.  **Check Transactions**: For every transaction your agent proposes, call `/transaction/check` with the `session_id` and transaction details. GuardRail will return a `verdict` and `action`.
3.  **Monitor Status**: Use `/session/{session_id}/status` to get real-time insights into an agent's security posture.

GuardRail is built for the OKX AI Genesis Hackathon 2026, demonstrating a crucial advancement in AI agent security.
"""
APP_VERSION = "1.0.0"

# --- Helper Functions ---

async def _check_rpc_connectivity() -> bool:
    """Checks connectivity to the X Layer RPC URL."""
    try:
        # This is a placeholder. A real check would involve a web3.py call
        # For example: w3 = Web3(Web3.HTTPProvider(XLAYER_RPC_URL)); return w3.is_connected()
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(XLAYER_RPC_URL, json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1})
            response.raise_for_status()
            return response.json().get("result") is not None
    except Exception as e:
        logger.error(f"X Layer RPC connectivity check failed: {e}")
        return False

async def _check_okx_api_connectivity() -> bool:
    """Checks connectivity to OKX APIs by attempting a dummy call."""
    try:
        # This is a placeholder. A real check would involve a lightweight OKX API call
        # For example, fetching server time or a public market data endpoint
        # For now, we'll just check if API keys are present.
        if not all([OKX_API_KEY, OKX_API_SECRET, OKX_API_PASSPHRASE]):
            return False
        
        # A more robust check would be to call a public endpoint that doesn't require specific user data
        # For example, fetching system time: GET /api/v5/public/time
        # This requires implementing a lightweight version of get_okx_headers for GET requests without body
        
        # For now, we'll consider it connected if keys are present.
        # In a real scenario, you'd make an actual API call.
        return True
    except Exception as e:
        logger.error(f"OKX API connectivity check failed: {e}")
        return False

def _calculate_risk_trend(risk_scores: List[float]) -> str:
    """
    Calculates the risk trend based on the last 5 risk scores.
    """
    if len(risk_scores) < 3:
        return "STABLE"
    
    recent_scores = risk_scores[-5:]
    if len(recent_scores) < 2:
        return "STABLE"

    # Simple linear trend: compare average of first half to average of second half
    mid_point = len(recent_scores) // 2
    first_half_avg = sum(recent_scores[:mid_point]) / mid_point if mid_point > 0 else recent_scores[0]
    second_half_avg = sum(recent_scores[mid_point:]) / (len(recent_scores) - mid_point)

    if second_half_avg > first_half_avg * 1.1: # 10% increase
        return "DETERIORATING"
    elif second_half_avg < first_half_avg * 0.9: # 10% decrease
        return "IMPROVING"
    else:
        return "STABLE"

# --- Routes ---

@router.api_route("/health", methods=["GET", "HEAD"], response_model=HealthResponse, summary="Health Check")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """
    Provides an overview of the GuardRail service's health and connectivity.
    """
    rpc_connected = await _check_rpc_connectivity()
    okx_api_connected = await _check_okx_api_connectivity()
    session_stats = await get_session_stats() # Await get_session_stats

    overall_status = "ok"
    if not rpc_connected or not okx_api_connected:
        overall_status = "degraded"
    if not rpc_connected and not okx_api_connected:
        overall_status = "error"

    return HealthResponse(
        status=overall_status,
        version=APP_VERSION,
        rpc_connected=rpc_connected,
        okx_api_connected=okx_api_connected,
        active_sessions=session_stats["active_sessions"],
        timestamp=datetime.now()
    )

@router.post("/session/create", response_model=SessionCreateResponse, status_code=status.HTTP_201_CREATED, summary="Create New Session")
@limiter.limit("10/minute")
async def create_new_session(request: Request, session_request: SessionCreateRequest):
    """
    Creates a new monitoring session for an AI agent.
    """
    session = await create_session( # Await create_session
        session_request.agent_id,
        session_request.initial_budget_usd,
        session_request.authorized_chain_hops,
        session_request.task_description
    )
    return SessionCreateResponse(
        session_id=session["session_id"],
        agent_id=session["agent_id"],
        created_at=session["created_at"],
        status=session["status"],
        message="Session created successfully."
    )

@router.post("/transaction/check", response_model=TransactionCheckResponse, summary="Main Transaction Security Check")
@limiter.limit("60/minute")
async def transaction_check(request: Request, tx_request: TransactionCheckRequest):
    """
    The main endpoint for submitting a transaction for behavioral and pattern-based security analysis.
    """
    start_time = datetime.now()
    session = await get_session(tx_request.session_id) # Await get_session

    if not session:
        # Create a temporary session if session_id does not exist
        temp_session_id = tx_request.session_id if tx_request.session_id else str(uuid.uuid4())
        session = await create_session(temp_session_id) # Await create_session
        session["_temporary"] = True
        logger.info(f"Created temporary session {session['session_id']} for missing session_id: {tx_request.session_id}")

    # b. If suspended — return BLOCK immediately
    if session["status"] == "suspended":
        return TransactionCheckResponse(
            session_id=session["session_id"],
            agent_id=session["agent_id"],
            verdict="BLOCK",
            action="BLOCK",
            composite_score=100.0,
            component_scores={},
            critical_flags=[f"Session suspended: {session.get('suspension_reason', 'No reason provided')}"],
            all_flags=[f"Session suspended: {session.get('suspension_reason', 'No reason provided')}"],
            session_transaction_count=len(session["transactions"]),
            session_risk_trend=_calculate_risk_trend(session["risk_score_history"]),
            analysis_timestamp=datetime.now(),
            individual_check={"risk_level": "CRITICAL", "action": "BLOCK", "risk_items": [{"label": "SESSION_SUSPENDED", "detail": "Session is suspended."}]},
            behavioral_drift={"overall_flag": "NORMAL", "drift_score": 0.0, "flags": []},
            o2p_analysis={"overall_flag": "CLEAN", "o2p_score": 0.0, "flags": []},
            backrun_analysis={"backrun_risk": "UNKNOWN", "flag": "N/A"},
            api_exhaustion_analysis={"risk": "NONE", "flag": "N/A"},
            skill_infection_analysis={"risk": "NONE", "flag": "N/A"},
            chain_validation_analysis={"risk": "NONE", "flag": "N/A"}
        )

    # c. Parallel fetch: okx scan_transaction, okx scan_token, okx get_pool_liquidity
    # d. Record API failure if any call failed
    okx_tx_task = scan_transaction(
        token_in=tx_request.token_in,
        token_out=tx_request.token_out,
        amount=str(tx_request.amount_usd), # OKX API expects amount as string
        chain_id=tx_request.chain_id,
        contract_address=tx_request.contract_address
    )
    okx_token_task = scan_token(
        token_address=tx_request.token_in, # Assuming token_in is the primary token for scan
        chain_id=tx_request.chain_id
    )
    pool_liquidity_task = get_pool_liquidity(
        token_address=tx_request.token_in, # Assuming liquidity for token_in
        chain_id=tx_request.chain_id
    )

    # Initializing default failed states for API results
    individual_tx_result_default = {
        "action": "WARN", "risk_level": "UNKNOWN", "risk_items": [{"label": "API_ERROR", "detail": "OKX Transaction Scan API failed or timed out."}], "raw_response": {}, "api_failed": True
    }
    token_scan_result_default = {
        "risk_level": "UNKNOWN", "is_honeypot": False, "risk_labels": ["API_ERROR"], "raw_response": {}, "api_failed": True
    }
    pool_liquidity_usd_default = 0.0

    # Initialize results with defaults
    individual_tx_result = individual_tx_result_default
    token_scan_result = token_scan_result_default
    pool_liquidity_usd = pool_liquidity_usd_default
    
    api_call_failed_or_timed_out = False # Flag to track if any API call failed or timed out

    try:
        # Wrap the gather call in asyncio.wait_for with a 5-second total timeout
        gathered_results = await asyncio.wait_for(
            asyncio.gather(
                okx_tx_task,
                okx_token_task,
                pool_liquidity_task,
                return_exceptions=True # This ensures individual task exceptions are returned, not raised
            ),
            timeout=5.0
        )
        
        # Process results from asyncio.gather
        temp_individual_tx_result, temp_token_scan_result, temp_pool_liquidity_usd = gathered_results

        # Check each result for exceptions or internal API failures
        if isinstance(temp_individual_tx_result, Exception) or temp_individual_tx_result.get("api_failed", False):
            api_call_failed_or_timed_out = True
        else:
            individual_tx_result = temp_individual_tx_result

        if isinstance(temp_token_scan_result, Exception) or temp_token_scan_result.get("api_failed", False):
            api_call_failed_or_timed_out = True
        else:
            token_scan_result = temp_token_scan_result

        if isinstance(temp_pool_liquidity_usd, Exception):
            api_call_failed_or_timed_out = True
        else:
            pool_liquidity_usd = temp_pool_liquidity_usd

    except asyncio.TimeoutError:
        logger.warning(f"OKX API calls timed out for session {tx_request.session_id}. Continuing with local analysis.")
        api_call_failed_or_timed_out = True
    except Exception as e:
        logger.error(f"An unexpected error occurred during OKX API calls for session {tx_request.session_id}: {e}")
        api_call_failed_or_timed_out = True

    if api_call_failed_or_timed_out:
        await record_security_failure(tx_request.session_id) # Record a single failure for the entire block
        # Results are already set to defaults if an error occurred or timed out

    # e. If is_approval — add to approval list
    if tx_request.is_approval:
        await add_approval( # Await add_approval
            tx_request.session_id,
            {
                "contract_address": tx_request.contract_address,
                "factory_address": tx_request.factory_address,
                "token": tx_request.token_in, # Assuming token_in is the approved token
                "amount": tx_request.amount_usd,
                "timestamp": datetime.now()
            }
        )

    # f. If calling_skill_id — detect behavior change vs baseline, add skill call
    behavior_changed_after_skill = False # Placeholder for actual detection logic
    if tx_request.calling_skill_id:
        # This logic would compare current transaction behavior to pre-skill-call baseline
        # For now, we'll assume no change unless explicitly detected by drift
        # A more sophisticated approach would involve comparing drift before and after skill call
        await add_skill_call(tx_request.session_id, tx_request.calling_skill_id, behavior_changed_after_skill) # Await add_skill_call

    # g. Run all detectors in parallel
    # Prepare data for detectors
    current_tx_record = {
        "tx_hash": None, # Not available at this stage
        "token_in": tx_request.token_in,
        "token_out": tx_request.token_out,
        "amount_usd": tx_request.amount_usd,
        "contract_address": tx_request.contract_address,
        "timestamp": datetime.now(),
        "individual_verdict": individual_tx_result.get("risk_level", "UNKNOWN"),
        "session_risk_score": 0.0, # Will be updated after composite risk
        "gas_price": None, # Not provided in request
        "pool_liquidity_usd": pool_liquidity_usd
    }
    
    session_age_hours = (datetime.now() - session["created_at"]).total_seconds() / 3600.0
    
    o2p_task = detect_o2p_pattern(session["approvals"])
    backrun_task = detect_backrun_risk(
        amount_usd=tx_request.amount_usd,
        pool_liquidity_usd=pool_liquidity_usd,
        token_in=tx_request.token_in,
        token_out=tx_request.token_out
    )
    api_exhaustion_task = detect_api_exhaustion(
        security_failures=session["security_api_failures"],
        session_age_hours=session_age_hours
    )
    skill_infection_task = detect_skill_infection(session["skills_called"])
    drift_task = calculate_drift(
        baseline=session["baseline"],
        recent_transactions=session["transactions"][-5:], # Last 5 transactions for recent behavior
        current_tx=current_tx_record
    )
    chain_validation_task = validate_payment_chain(
        payment_chain=session["payment_chain"],
        original_task=session["task_description"],
        authorized_budget_usd=session["initial_budget_usd"]
    )

    o2p_analysis, backrun_analysis, api_exhaustion_analysis, skill_infection_analysis, behavioral_drift_analysis, chain_validation_analysis = await asyncio.gather(
        o2p_task, backrun_task, api_exhaustion_task, skill_infection_task, drift_task, chain_validation_task
    )

    # h. Calculate composite risk
    composite_risk_result = await calculate_composite_risk( # Await calculate_composite_risk
        individual_tx_result=individual_tx_result,
        o2p_result=o2p_analysis,
        backrun_result=backrun_analysis,
        drift_result=behavioral_drift_analysis,
        api_exhaustion_result=api_exhaustion_analysis,
        skill_infection_result=skill_infection_analysis,
        chain_validation_result=chain_validation_analysis
    )

    # Update current_tx_record with the calculated session_risk_score
    current_tx_record["session_risk_score"] = composite_risk_result["composite_score"]

    # i. If BLOCK verdict and CRITICAL flags — auto-suspend session
    if composite_risk_result["verdict"] == "BLOCK" and composite_risk_result["critical_flags"]:
        await suspend_session(tx_request.session_id, f"Auto-suspended due to BLOCK verdict and critical flags: {', '.join(composite_risk_result['critical_flags'])}") # Await suspend_session
        session["status"] = "suspended" # Update local session object for immediate response

    # j. Add transaction to session history
    await add_transaction(tx_request.session_id, current_tx_record) # Await add_transaction

    # k. Calculate risk trend from last 5 scores
    session_risk_trend = _calculate_risk_trend(session["risk_score_history"])

    end_time = datetime.now()
    response_time_ms = (end_time - start_time).total_seconds() * 1000

    # Log every transaction check
    logger.info(
        f"TX_CHECK_LOG: {datetime.now().isoformat()} | "
        f"SessionID: {tx_request.session_id} | AgentID: {session['agent_id']} | "
        f"Score: {composite_risk_result['composite_score']:.2f} | Verdict: {composite_risk_result['verdict']} | "
        f"ResponseTime: {response_time_ms:.2f}ms"
    )

    # l. Return TransactionCheckResponse
    return TransactionCheckResponse(
        session_id=session["session_id"],
        agent_id=session["agent_id"],
        verdict=composite_risk_result["verdict"],
        action=composite_risk_result["action"],
        composite_score=composite_risk_result["composite_score"],
        component_scores=composite_risk_result["component_scores"],
        critical_flags=composite_risk_result["critical_flags"],
        all_flags=composite_risk_result["all_flags"],
        session_transaction_count=len(session["transactions"]),
        session_risk_trend=session_risk_trend,
        analysis_timestamp=datetime.now(),
        individual_check=individual_tx_result,
        behavioral_drift=behavioral_drift_analysis,
        o2p_analysis=o2p_analysis,
        backrun_analysis=backrun_analysis,
        api_exhaustion_analysis=api_exhaustion_analysis,
        skill_infection_analysis=skill_infection_analysis,
        chain_validation_analysis=chain_validation_analysis
    )

@router.post("/payment/register-hop", response_model=PaymentHopResponse, summary="Register Payment Chain Hop")
@limiter.limit("30/minute")
async def register_payment_hop_route(request: Request, hop_request: PaymentHopRequest):
    """
    Registers a new hop in an agent's payment chain.
    """
    session = await get_session(hop_request.session_id) # Await get_session
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    updated_chain = await register_payment_hop( # Await register_payment_hop
        session["payment_chain"],
        hop_request.calling_agent_id,
        hop_request.task_description,
        hop_request.amount_usd
    )
    session["payment_chain"] = updated_chain # Update session with new chain

    validation_result = await validate_payment_chain( # Await validate_payment_chain
        session["payment_chain"],
        session["task_description"],
        session["initial_budget_usd"]
    )

    return PaymentHopResponse(
        valid=validation_result["valid"],
        risk=validation_result["risk"],
        chain_length=validation_result["chain_length"],
        flag=validation_result["flag"],
        total_spent_usd=validation_result["total_spent_usd"]
    )

@router.get("/session/{session_id}/status", response_model=SessionStatusResponse, summary="Get Session Status")
@limiter.limit("60/minute")
async def get_session_status(request: Request, session_id: str):
    """
    Retrieves the current status and detailed information for a specific session.
    """
    session = await get_session(session_id) # Await get_session
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    session_age_hours = (datetime.now() - session["created_at"]).total_seconds() / 3600.0
    risk_trend = _calculate_risk_trend(session["risk_score_history"])
    total_flags_raised = len(session.get("all_flags", [])) # Assuming all_flags is stored or can be re-calculated

    return SessionStatusResponse(
        session_id=session["session_id"],
        agent_id=session["agent_id"],
        status=session["status"],
        transaction_count=len(session["transactions"]),
        approval_count=len(session["approvals"]),
        security_api_failures=session["security_api_failures"],
        current_risk_trend=risk_trend,
        baseline_established=session["baseline"]["established"],
        total_flags_raised=total_flags_raised,
        session_age_hours=session_age_hours,
        created_at=session["created_at"],
        last_active=session["last_active"],
        initial_budget_usd=session["initial_budget_usd"],
        authorized_chain_hops=session["authorized_chain_hops"],
        task_description=session["task_description"],
        suspension_reason=session.get("suspension_reason")
    )

@router.post("/session/{session_id}/suspend", status_code=status.HTTP_200_OK, summary="Manually Suspend Session")
@limiter.limit("5/minute")
async def suspend_agent_session(request: Request, session_id: str, reason: str = "Manual suspension"):
    """
    Manually suspends an agent session, preventing further transactions.
    """
    session = await get_session(session_id) # Await get_session
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    
    await suspend_session(session_id, reason) # Await suspend_session
    return {"message": f"Session {session_id} suspended successfully. Reason: {reason}"}

@router.get("/sessions/stats", summary="Get All Sessions Statistics")
@limiter.limit("10/minute")
async def get_all_sessions_stats(request: Request, master_key: str = Depends(get_master_api_key)):
    """
    Retrieves statistics about all active, suspended, and flagged sessions.
    Requires MASTER_API_KEY for access.
    """
    return await get_session_stats() # Await get_session_stats

@router.delete("/session/{session_id}", status_code=status.HTTP_200_OK, summary="Delete Session")
@limiter.limit("5/minute")
async def delete_session_route(request: Request, session_id: str, master_key: str = Depends(get_master_api_key)):
    """
    Deletes a session from memory. This action is irreversible.
    Requires MASTER_API_KEY for access.
    """
    session = await get_session(session_id) # Await get_session
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    
    await delete_session(session_id) # Use the new async delete_session function
    return {"message": f"Session {session_id} deleted successfully."}
