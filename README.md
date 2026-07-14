# GuardRail — Behavioral Security Intelligence for OKX.AI Agents

GuardRail is an Agent Service Provider (ASP) listed on OKX.AI that provides a critical, missing layer of security: **behavioral intelligence and session security monitoring for AI agents operating on OKX.AI and X Layer.**

## 1. The Problem

Existing security tools, including OKX's own `okx-security` skill, check **individual transactions in isolation**. This leaves a significant vulnerability for sophisticated, cumulative attacks that exploit patterns over time.

-   **O2P (Overhang-to-Position) Attacks**: Identified in a **May 2026 academic paper on OKX Agent Payments Protocol**, these attacks involve multiple individually-safe approvals building toward critical exposure. The **JaredFromSubway $7.5M loss (June 20, 2026)** was caused by accumulated approvals that each passed individual checks.
-   **OWASP Behavioral Drift Detection Gap**: The **OWASP March 2026 proposal on Behavioral Drift Detection** explicitly states that "no mechanism to establish normal behavior for an agent and detect deviations from that baseline" exists. This highlights a critical, unsolved problem in AI agent security.
-   **Backrun Losses**: A **$2M backrun loss (July 7, 2026)** was caused by low-liquidity routing that passed slippage checks, demonstrating how per-transaction checks fail to capture market manipulation risks.

## 2. What GuardRail Does

GuardRail monitors the **pattern of transactions across an entire agent session** and detects attacks that are invisible to per-transaction checks. It wraps OKX's own security tools and adds the longitudinal intelligence layer they are missing.

## 3. Why GuardRail Is Different

**Every other tool checks ONE transaction. GuardRail monitors the PATTERN.**

GuardRail provides a holistic view of agent behavior, identifying anomalies and malicious patterns that are missed by traditional, point-in-time security checks.

## 4. API Endpoints

| Method | Endpoint                       | Description                                                              | Authentication |
| :----- | :----------------------------- | :----------------------------------------------------------------------- | :------------- |
| `GET`  | `/api/v1/health`               | Provides an overview of the GuardRail service's health and connectivity. | None           |
| `POST` | `/api/v1/session/create`       | Creates a new monitoring session for an AI agent.                        | None           |
| `POST` | `/api/v1/transaction/check`    | **MAIN ENDPOINT**: Submits a transaction for security analysis.          | None           |
| `POST` | `/api/v1/payment/register-hop` | Registers a new hop in an agent's payment chain.                         | None           |
| `GET`  | `/api/v1/session/{session_id}/status` | Retrieves the current status and detailed information for a session.     | None           |
| `POST` | `/api/v1/session/{session_id}/suspend` | Manually suspends an agent session.                                      | None           |
| `GET`  | `/api/v1/sessions/stats`       | Retrieves statistics about all sessions.                                 | `X-API-Key`    |
| `DELETE`| `/api/v1/session/{session_id}` | Deletes a session from memory.                                           | `X-API-Key`    |

## 5. Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/guardrail.git
    cd guardrail
    ```
2.  **Set up environment variables:**
    Copy `.env.example` to `.env` and fill in your OKX API credentials and other configurations.
    ```bash
    cp .env.example .env
    # Open .env and edit
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the application:**
    ```bash
    python main.py
    ```
    The API will be available at `http://localhost:8000` (or your configured `PORT`).

## 6. Integration Guide (3 Steps)

Integrating GuardRail into your AI agent workflow is straightforward:

1.  **Create a Session**:
    Call the `/api/v1/session/create` endpoint with your `agent_id` to initiate a new monitoring session. You will receive a `session_id` in response.
    ```json
    POST /api/v1/session/create
    {
      "agent_id": "my_ai_agent_123",
      "initial_budget_usd": 1000.0,
      "task_description": "Execute arbitrage strategy on X Layer"
    }
    ```
2.  **Check Transactions**:
    For every transaction your agent proposes, call the `/api/v1/transaction/check` endpoint, including the `session_id` and full transaction details. GuardRail will return a `verdict` and `action`.
    ```json
    POST /api/v1/transaction/check
    {
      "session_id": "your_session_id_here",
      "token_in": "0x...",
      "token_out": "0x...",
      "amount_usd": 100.50,
      "contract_address": "0x...",
      "chain_id": 196,
      "is_approval": false,
      "calling_skill_id": "okx_swap_skill"
    }
    ```
3.  **Monitor Status**:
    Use the `/api/v1/session/{session_id}/status` endpoint to get real-time insights into an agent's security posture, including risk trends, flags, and baseline information.

## 7. Detection Capabilities with Real Incidents

GuardRail's detection capabilities are designed to address documented vulnerabilities in AI agent operations:

-   **O2P (Overhang-to-Position) Attacks**: Detects accumulation of individually small approvals that lead to critical exposure.
    *Real Incident*: JaredFromSubway's $7.5M loss (June 20, 2026) due to accumulated approvals.
-   **Behavioral Drift Detection**: Identifies deviations from an agent's normal transaction patterns (e.g., sudden changes in transaction size, frequency, or contract types).
    *Real-world Relevance*: Addresses the OWASP March 2026 proposal on Behavioral Drift Detection, providing the first working implementation.
-   **Backrun Risk**: Flags transactions that are susceptible to backrunning due to low liquidity or large trade sizes relative to pool depth.
    *Real Incident*: $2M backrun loss (July 7, 2026) caused by low-liquidity routing.
-   **API Exhaustion**: Monitors for deliberate attempts to bypass security by overwhelming or failing security API calls.
    *Real-world Relevance*: Addresses a known vulnerability where OKX security auto-continues on failure in swap contexts.
-   **Skill Infection**: Detects suspicious behavioral changes in an agent after it interacts with a new or potentially compromised Agent Service Provider (ASP).
    *Real-world Relevance*: Inspired by the 824 malicious skills found in the OpenClaw ecosystem early 2026.

## 8. Example Full JSON Response

```json
{
  "session_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "agent_id": "my_ai_agent_123",
  "verdict": "WARN",
  "action": "REVIEW",
  "composite_score": 55.75,
  "component_scores": {
    "individual_tx": 30.0,
    "pattern_score": 40.0,
    "behavioral_drift": 45.0,
    "chain_validation": 0.0,
    "backrun_risk": 60.0,
    "api_exhaustion": 0.0,
    "skill_infection": 0.0
  },
  "critical_flags": [],
  "all_flags": [
    "WARNING: Elevated approval count (5) detected.",
    "WARNING: Transaction amount (Z-score 2.50) significantly deviates from baseline.",
    "WARNING: Trade amount is a high percentage of pool liquidity, indicating elevated backrun risk."
  ],
  "session_transaction_count": 5,
  "session_risk_trend": "DETERIORATING",
  "analysis_timestamp": "2026-07-13T10:30:00.123456",
  "individual_check": {
    "action": "WARN",
    "risk_level": "MEDIUM",
    "risk_items": [
      {
        "label": "SuspiciousContract",
        "detail": "Contract has low reputation"
      }
    ],
    "raw_response": {},
    "api_failed": false
  },
  "behavioral_drift": {
    "drift_score": 45.0,
    "z_amount": 2.5,
    "frequency_ratio": 1.5,
    "frequency_flag": "HIGH_FREQUENCY",
    "contract_flag": "KNOWN_TYPE",
    "time_flag": "ACTIVE_HOURS",
    "drift_velocity": 0.8,
    "flags": [
      "WARNING: Transaction amount (Z-score 2.50) significantly deviates from baseline."
    ],
    "overall_flag": "DRIFTING",
    "method": "behavioral_drift_detection"
  },
  "o2p_analysis": {
    "o2p_score": 40.0,
    "total_approvals": 5,
    "total_exposed_usd": 1500.0,
    "max_factory_cluster": 3,
    "approvals_per_hour": 1.25,
    "flags": [
      "WARNING: Elevated approval count (5) detected."
    ],
    "overall_flag": "ACCUMULATING",
    "method": "o2p_pattern_detection"
  },
  "backrun_analysis": {
    "backrun_risk": "HIGH",
    "liquidity_ratio": 0.1,
    "pool_liquidity_usd": 100000.0,
    "trade_amount_usd": 10000.0,
    "flag": "WARNING: Trade amount is a high percentage of pool liquidity, indicating elevated backrun risk.",
    "method": "backrun_risk_detection"
  },
  "api_exhaustion_analysis": {
    "risk": "NONE",
    "failure_count": 0,
    "failure_rate_per_hour": 0.0,
    "flag": "No API exhaustion risk detected.",
    "method": "api_exhaustion_detection"
  },
  "skill_infection_analysis": {
    "risk": "NONE",
    "infected_skills": [],
    "flag": "No skill infection detected.",
    "method": "skill_infection_detection"
  },
  "chain_validation_analysis": {
    "valid": true,
    "risk": "SAFE",
    "chain_length": 1,
    "total_spent_usd": 10.0,
    "budget_remaining_usd": 90.0,
    "flag": "Payment chain is valid.",
    "method": "chain_validation"
  }
}
```

## 9. Research Backing

-   **May 2026 academic paper on OKX Agent Payments Protocol**: This paper formally identified "O2P (Overhang-to-Position)" as a critical, unsolved cumulative attack vector, which GuardRail directly addresses.
-   **OWASP March 2026 proposal on Behavioral Drift Detection**: This proposal highlighted the lack of mechanisms to establish and detect deviations from normal agent behavior. GuardRail provides the first working implementation of such a mechanism.
-   **Sherlock 2026 report**: This comprehensive report detailed various sophisticated attack vectors targeting AI agents, many of which involve multi-step or cumulative actions that GuardRail is designed to detect.

## 10. Built for OKX AI Genesis Hackathon 2026

GuardRail is a submission for the OKX AI Genesis Hackathon 2026, aiming to provide a robust and innovative security solution for the OKX.AI and X Layer ecosystem.