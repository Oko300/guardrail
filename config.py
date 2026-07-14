import os
from dotenv import load_dotenv

load_dotenv()

# Environment Variables
XLAYER_RPC_URL = os.getenv("XLAYER_RPC_URL", "https://rpc.xlayer.tech")
OKX_API_KEY = os.getenv("OKX_API_KEY")
OKX_API_SECRET = os.getenv("OKX_API_SECRET")
OKX_API_PASSPHRASE = os.getenv("OKX_API_PASSPHRASE")
OKX_TX_SCAN_URL = os.getenv("OKX_TX_SCAN_URL")
OKX_TOKEN_SCAN_URL = os.getenv("OKX_TOKEN_SCAN_URL")
MASTER_API_KEY = os.getenv("MASTER_API_KEY", "guardrail_master_key")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", 300))
PORT = int(os.getenv("PORT", 8000))
XLAYER_CHAIN_ID = int(os.getenv("XLAYER_CHAIN_ID", 196))

# Constants
RISK_WEIGHTS = {
    "individual_tx": 0.25,
    "pattern_score": 0.35,
    "behavioral_drift": 0.25,
    "chain_validation": 0.15
}

O2P_THRESHOLDS = {
    "approval_count_warning": 5,
    "approval_count_critical": 10,
    "same_factory_warning": 3,
    "same_factory_critical": 5,
    "exposure_warning_usd": 1000,
    "exposure_critical_usd": 5000,
    "time_window_hours": 4
}

DRIFT_THRESHOLDS = {
    "velocity_warning": 3.0,
    "velocity_critical": 5.0,
    "size_deviation_warning": 2.0,
    "size_deviation_critical": 4.0,
    "frequency_deviation_warning": 3.0,
    "frequency_deviation_critical": 5.0
}

BACKRUN_THRESHOLDS = {
    "pool_liquidity_ratio_warning": 0.05,
    "pool_liquidity_ratio_critical": 0.10,
    "min_pool_liquidity_usd": 100000
}

API_EXHAUSTION_THRESHOLD = 5
PAYMENT_CHAIN_MAX_HOPS = 3
SESSION_TIMEOUT_HOURS = 24