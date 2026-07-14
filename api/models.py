from datetime import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel, Field

class SessionCreateRequest(BaseModel):
    """
    Request model for creating a new session.
    """
    agent_id: str = Field(..., description="Unique identifier for the AI agent.")
    initial_budget_usd: float = Field(0.0, description="Initial budget authorized for the agent in USD.")
    authorized_chain_hops: int = Field(3, description="Maximum number of payment chain hops authorized.")
    task_description: str = Field("", description="Description of the task the agent is performing.")

class SessionCreateResponse(BaseModel):
    """
    Response model for a newly created session.
    """
    session_id: str = Field(..., description="Unique identifier for the session.")
    agent_id: str = Field(..., description="ID of the AI agent.")
    created_at: datetime = Field(..., description="Timestamp when the session was created.")
    status: str = Field(..., description="Current status of the session (e.g., 'active', 'suspended').")
    message: str = Field(..., description="A descriptive message about the session creation.")

class TransactionCheckRequest(BaseModel):
    """
    Request model for checking a transaction.
    """
    session_id: str = Field(..., description="Unique identifier for the session.")
    token_in: str = Field(..., description="Address of the token being sent.")
    token_out: str = Field(..., description="Address of the token being received.")
    amount_usd: float = Field(..., description="Amount of the transaction in USD.")
    contract_address: str = Field(..., description="The contract address involved in the transaction.")
    chain_id: int = Field(196, description="Chain ID (e.g., 196 for X Layer).")
    is_approval: bool = Field(False, description="True if this transaction is an approval event.")
    factory_address: Optional[str] = Field(None, description="Factory address if known for approval events.")
    calling_skill_id: Optional[str] = Field(None, description="ID of the skill (ASP) that initiated this transaction.")

class TransactionCheckResponse(BaseModel):
    """
    Response model for a transaction check.
    """
    session_id: str = Field(..., description="Unique identifier for the session.")
    agent_id: str = Field(..., description="ID of the AI agent.")
    verdict: str = Field(..., description="Overall security verdict ('SAFE', 'WARN', 'BLOCK').")
    action: str = Field(..., description="Recommended action ('ALLOW', 'REVIEW', 'BLOCK').")
    composite_score: float = Field(..., description="GuardRail's composite risk score (0-100).")
    component_scores: Dict[str, float] = Field(..., description="Scores from individual security components.")
    critical_flags: List[str] = Field(..., description="List of critical flags raised.")
    all_flags: List[str] = Field(..., description="List of all flags raised (critical and warning).")
    session_transaction_count: int = Field(..., description="Total transactions in this session.")
    session_risk_trend: str = Field(..., description="Trend of session risk ('IMPROVING', 'STABLE', 'DETERIORATING').")
    analysis_timestamp: datetime = Field(..., description="Timestamp of this analysis.")
    individual_check: Dict = Field(..., description="Details from the individual transaction security check.")
    behavioral_drift: Dict = Field(..., description="Details from behavioral drift analysis.")
    o2p_analysis: Dict = Field(..., description="Details from O2P pattern analysis.")
    backrun_analysis: Dict = Field(..., description="Details from backrun risk analysis.")
    api_exhaustion_analysis: Dict = Field(..., description="Details from API exhaustion analysis.")
    skill_infection_analysis: Dict = Field(..., description="Details from skill infection analysis.")
    chain_validation_analysis: Dict = Field(..., description="Details from payment chain validation.")


class PaymentHopRequest(BaseModel):
    """
    Request model for registering a payment chain hop.
    """
    session_id: str = Field(..., description="Unique identifier for the session.")
    calling_agent_id: str = Field(..., description="ID of the agent making this payment hop.")
    task_description: str = Field(..., description="Description of the task for this payment hop.")
    amount_usd: float = Field(..., description="Amount spent in USD for this payment hop.")
    authorized_budget_usd: float = Field(..., description="Total budget authorized for the entire payment chain in USD.")

class PaymentHopResponse(BaseModel):
    """
    Response model for a payment hop registration.
    """
    valid: bool = Field(..., description="True if the payment chain is currently valid.")
    risk: str = Field(..., description="Overall risk level of the payment chain ('NONE', 'WARNING', 'CRITICAL').")
    chain_length: int = Field(..., description="Current length of the payment chain.")
    flag: str = Field(..., description="A descriptive flag about the payment chain status.")
    total_spent_usd: float = Field(..., description="Total amount spent in USD across the entire payment chain.")

class SessionStatusResponse(BaseModel):
    """
    Response model for retrieving session status.
    """
    session_id: str = Field(..., description="Unique identifier for the session.")
    agent_id: str = Field(..., description="ID of the AI agent.")
    status: str = Field(..., description="Current status of the session ('active', 'suspended', 'flagged').")
    transaction_count: int = Field(..., description="Total number of transactions recorded in this session.")
    approval_count: int = Field(..., description="Total number of approval events recorded in this session.")
    security_api_failures: int = Field(..., description="Number of security API failures for this session.")
    current_risk_trend: str = Field(..., description="Current risk trend of the session ('IMPROVING', 'STABLE', 'DETERIORATING').")
    baseline_established: bool = Field(..., description="True if a behavioral baseline has been established for this session.")
    total_flags_raised: int = Field(..., description="Total number of flags (critical and warning) raised for this session.")
    session_age_hours: float = Field(..., description="Age of the session in hours.")
    created_at: datetime = Field(..., description="Timestamp when the session was created.")
    last_active: datetime = Field(..., description="Timestamp of the last activity in the session.")
    initial_budget_usd: float = Field(..., description="Initial budget authorized for the agent in USD.")
    authorized_chain_hops: int = Field(..., description="Maximum number of payment chain hops authorized.")
    task_description: str = Field(..., description="Description of the task the agent is performing.")
    suspension_reason: Optional[str] = Field(None, description="Reason for suspension, if applicable.")


class HealthResponse(BaseModel):
    """
    Response model for the health check endpoint.
    """
    status: str = Field(..., description="Overall health status ('ok', 'degraded', 'error').")
    version: str = Field(..., description="Application version.")
    rpc_connected: bool = Field(..., description="Status of X Layer RPC connection.")
    okx_api_connected: bool = Field(..., description="Status of OKX API connectivity.")
    active_sessions: int = Field(..., description="Number of currently active sessions.")
    timestamp: datetime = Field(..., description="Timestamp of the health check.")