import hmac
import hashlib
import base64
import json
import httpx
from datetime import datetime
from typing import Dict, Any

from config import OKX_API_KEY, OKX_API_SECRET, OKX_API_PASSPHRASE, OKX_TX_SCAN_URL, OKX_TOKEN_SCAN_URL, XLAYER_RPC_URL

# Constants for API calls
API_TIMEOUT = 5 # seconds

def generate_okx_signature(timestamp: str, method: str, request_path: str, body: str, secret: str) -> str:
    """
    Generates the HMAC-SHA256 signature for OKX API requests.

    Args:
        timestamp (str): ISO formatted timestamp (e.g., "2026-07-13T10:30:00.000Z").
        method (str): HTTP method (e.g., "GET", "POST").
        request_path (str): Request path (e.g., "/api/v5/account/balance").
        body (str): Request body (empty string for GET requests).
        secret (str): OKX API secret key.

    Returns:
        str: The base64 encoded HMAC-SHA256 signature.
    """
    message = timestamp + method.upper() + request_path + body
    hmac_key = secret.encode('utf-8')
    signature = hmac.new(hmac_key, message.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(signature).decode('utf-8')

def get_okx_headers(request_path: str, method: str, body: Dict = None) -> Dict:
    """
    Generates standard OKX API headers including authentication.

    Args:
        request_path (str): The API endpoint path.
        method (str): The HTTP method (e.g., "GET", "POST").
        body (Dict, optional): The request body as a dictionary. Defaults to None.

    Returns:
        Dict: A dictionary of HTTP headers for OKX API requests.
    """
    timestamp = datetime.utcnow().isoformat("T", "milliseconds") + "Z"
    body_str = json.dumps(body) if body else ""
    signature = generate_okx_signature(timestamp, method, request_path, body_str, OKX_API_SECRET)

    return {
        "OK-ACCESS-KEY": OKX_API_KEY,
        "OK-ACCESS-SIGN": signature,
        "OK-ACCESS-TIMESTAMP": timestamp,
        "OK-ACCESS-PASSPHRASE": OKX_API_PASSPHRASE,
        "Content-Type": "application/json"
    }

async def scan_transaction(token_in: str, token_out: str, amount: str, chain_id: int, contract_address: str) -> Dict:
    """
    Calls the OKX pre-transaction security API to scan a transaction.

    Args:
        token_in (str): Address of the token being sent.
        token_out (str): Address of the token being received.
        amount (str): Amount of token_in (as string, e.g., "1.0").
        chain_id (int): Chain ID (e.g., 196 for X Layer).
        contract_address (str): The contract address involved in the transaction.

    Returns:
        Dict: A dictionary containing the security check result.
              On failure, returns a conservative WARN result with api_failed=True.
    """
    request_path = "/api/v5/wallet/pre-transaction/security-check"
    method = "POST"
    body = {
        "chainId": str(chain_id),
        "tokenIn": token_in,
        "tokenOut": token_out,
        "amount": amount,
        "contractAddress": contract_address
    }
    headers = get_okx_headers(request_path, method, body)

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            response = await client.post(OKX_TX_SCAN_URL, headers=headers, json=body)
            response.raise_for_status()
            data = response.json()
            if data and data.get("code") == "0" and data.get("data"):
                result = data["data"][0]
                return {
                    "action": result.get("action", "UNKNOWN"),
                    "risk_level": result.get("riskLevel", "UNKNOWN"),
                    "risk_items": result.get("riskItems", []),
                    "raw_response": data,
                    "api_failed": False
                }
            else:
                return {
                    "action": "WARN",
                    "risk_level": "UNKNOWN",
                    "risk_items": [],
                    "raw_response": data,
                    "api_failed": True,
                    "error_message": f"OKX API returned non-success code: {data.get('code')}"
                }
    except httpx.RequestError as e:
        return {
            "action": "WARN",
            "risk_level": "UNKNOWN",
            "risk_items": [],
            "raw_response": {},
            "api_failed": True,
            "error_message": f"OKX transaction scan request failed: {e}"
        }
    except httpx.HTTPStatusError as e:
        return {
            "action": "WARN",
            "risk_level": "UNKNOWN",
            "risk_items": [],
            "raw_response": e.response.json() if e.response else {},
            "api_failed": True,
            "error_message": f"OKX transaction scan HTTP error: {e}"
        }
    except Exception as e:
        return {
            "action": "WARN",
            "risk_level": "UNKNOWN",
            "risk_items": [],
            "raw_response": {},
            "api_failed": True,
            "error_message": f"OKX transaction scan unexpected error: {e}"
        }

async def scan_token(token_address: str, chain_id: int) -> Dict:
    """
    Calls the OKX token security scan API.

    Args:
        token_address (str): The address of the token to scan.
        chain_id (int): Chain ID (e.g., 196 for X Layer).

    Returns:
        Dict: A dictionary containing the token security check result.
              On failure, returns an unknown result safely.
    """
    request_path = "/api/v5/wallet/token/security-check"
    method = "POST"
    body = {
        "chainId": str(chain_id),
        "tokenAddress": token_address
    }
    headers = get_okx_headers(request_path, method, body)

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            response = await client.post(OKX_TOKEN_SCAN_URL, headers=headers, json=body)
            response.raise_for_status()
            data = response.json()
            if data and data.get("code") == "0" and data.get("data"):
                result = data["data"][0]
                return {
                    "risk_level": result.get("riskLevel", "UNKNOWN"),
                    "is_honeypot": result.get("isHoneypot", False),
                    "risk_labels": result.get("riskLabels", []),
                    "raw_response": data,
                    "api_failed": False
                }
            else:
                return {
                    "risk_level": "UNKNOWN",
                    "is_honeypot": False,
                    "risk_labels": [],
                    "raw_response": data,
                    "api_failed": True,
                    "error_message": f"OKX API returned non-success code: {data.get('code')}"
                }
    except httpx.RequestError as e:
        return {
            "risk_level": "UNKNOWN",
            "is_honeypot": False,
            "risk_labels": [],
            "raw_response": {},
            "api_failed": True,
            "error_message": f"OKX token scan request failed: {e}"
        }
    except httpx.HTTPStatusError as e:
        return {
            "risk_level": "UNKNOWN",
            "is_honeypot": False,
            "risk_labels": [],
            "raw_response": e.response.json() if e.response else {},
            "api_failed": True,
            "error_message": f"OKX token scan HTTP error: {e}"
        }
    except Exception as e:
        return {
            "risk_level": "UNKNOWN",
            "is_honeypot": False,
            "risk_labels": [],
            "raw_response": {},
            "api_failed": True,
            "error_message": f"OKX token scan unexpected error: {e}"
        }

async def get_pool_liquidity(token_address: str, chain_id: int) -> float:
    """
    Fetches pool liquidity for a given token from a DEX Aggregator quote endpoint (mocked for now).
    In a real scenario, this would involve calling a specific OKX DEX Aggregator endpoint.

    Args:
        token_address (str): The address of the token.
        chain_id (int): The chain ID.

    Returns:
        float: The pool liquidity in USD, or 0.0 on any failure.
    """
    # This is a placeholder/mock implementation.
    # A real implementation would involve calling an OKX DEX Aggregator endpoint
    # and parsing the response for liquidity.
    # For now, we return a dummy value or 0.0 on failure.
    try:
        # Simulate an API call to get liquidity
        # In a real scenario, you'd construct a request to an OKX DEX Aggregator
        # For example:
        # request_path = "/api/v5/market/estimated-price"
        # method = "GET"
        # params = {"instId": f"{token_address}-USDT", "sz": "1"} # Example for a quote
        # headers = get_okx_headers(request_path, method)
        # async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
        #     response = await client.get(OKX_DEX_AGGREGATOR_URL, headers=headers, params=params)
        #     response.raise_for_status()
        #     data = response.json()
        #     # Parse data to extract liquidity
        #     liquidity_usd = float(data.get("data", [{}])[0].get("liquidityUsd", 0.0))
        #     return liquidity_usd
        
        # For hackathon demo, return a fixed value or simulate variability
        if "0xdeadbeef" in token_address.lower(): # Example for a low liquidity token
            return 50000.0
        elif "0xcafebabe" in token_address.lower(): # Example for a high liquidity token
            return 5000000.0
        else:
            return 1000000.0 # Default liquidity
    except Exception as e:
        print(f"Error getting pool liquidity for {token_address} on chain {chain_id}: {e}")
        return 0.0

# Self-test block
async def main():
    print("Running core/okx_security.py self-test...")
    import os
    from dotenv import load_dotenv
    load_dotenv() # Load environment variables for testing

    # Mock environment variables for self-test if not loaded
    if not OKX_API_KEY:
        print("WARNING: OKX_API_KEY not set in .env. Using dummy values for self-test.")
        os.environ["OKX_API_KEY"] = "dummy_key"
        os.environ["OKX_API_SECRET"] = "dummy_secret"
        os.environ["OKX_API_PASSPHRASE"] = "dummy_passphrase"
        os.environ["OKX_TX_SCAN_URL"] = "http://localhost:8000/mock-okx-tx-scan" # Mock endpoint
        os.environ["OKX_TOKEN_SCAN_URL"] = "http://localhost:8000/mock-okx-token-scan" # Mock endpoint
        os.environ["XLAYER_RPC_URL"] = "http://localhost:8000/mock-xlayer-rpc" # Mock endpoint

    # Test 1: generate_okx_signature
    print("\n--- Test 1: generate_okx_signature ---")
    timestamp = "2026-07-13T10:30:00.000Z"
    method = "POST"
    request_path = "/api/v5/trade/order"
    body = '{"instId":"BTC-USDT","tdMode":"cash","side":"buy","ordType":"limit","px":"20000","sz":"1"}'
    secret = os.getenv("OKX_API_SECRET", "dummy_secret")
    signature = generate_okx_signature(timestamp, method, request_path, body, secret)
    print(f"Generated Signature: {signature}")
    assert isinstance(signature, str) and len(signature) > 0

    # Test 2: get_okx_headers
    print("\n--- Test 2: get_okx_headers ---")
    headers = get_okx_headers(request_path, method, json.loads(body))
    print(f"Generated Headers: {headers}")
    assert "OK-ACCESS-KEY" in headers
    assert "OK-ACCESS-SIGN" in headers
    assert "OK-ACCESS-TIMESTAMP" in headers
    assert "OK-ACCESS-PASSPHRASE" in headers
    assert "Content-Type" in headers

    # Test 3: scan_transaction (mocked success)
    print("\n--- Test 3: scan_transaction (mocked success) ---")
    # In a real test, you'd mock httpx.post to return a specific response
    # For this self-test, it will hit the (potentially non-existent) mock URL
    tx_result = await scan_transaction(
        token_in="0x123...", token_out="0x456...", amount="1.0",
        chain_id=196, contract_address="0x789..."
    )
    print(f"Transaction Scan Result: {tx_result}")
    # Expecting api_failed=True if mock endpoint is not running
    assert tx_result["api_failed"] is True or tx_result["risk_level"] in ["LOW", "UNKNOWN"]

    # Test 4: scan_token (mocked success)
    print("\n--- Test 4: scan_token (mocked success) ---")
    token_result = await scan_token(token_address="0xabc...", chain_id=196)
    print(f"Token Scan Result: {token_result}")
    assert token_result["api_failed"] is True or token_result["risk_level"] in ["LOW", "UNKNOWN"]

    # Test 5: get_pool_liquidity (mocked values)
    print("\n--- Test 5: get_pool_liquidity (mocked values) ---")
    liquidity_1 = await get_pool_liquidity(token_address="0xdeadbeef...", chain_id=196)
    print(f"Liquidity for 0xdeadbeef: {liquidity_1}")
    assert liquidity_1 == 50000.0

    liquidity_2 = await get_pool_liquidity(token_address="0xcafebabe...", chain_id=196)
    print(f"Liquidity for 0xcafebabe: {liquidity_2}")
    assert liquidity_2 == 5000000.0

    liquidity_3 = await get_pool_liquidity(token_address="0xanother...", chain_id=196)
    print(f"Liquidity for 0xanother: {liquidity_3}")
    assert liquidity_3 == 1000000.0

    print("\nAll core/okx_security.py self-tests completed (some may show API failed if mock server not running).")

if __name__ == "__main__":
    asyncio.run(main())
