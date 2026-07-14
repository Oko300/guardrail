from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from config import MASTER_API_KEY

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def get_master_api_key(api_key: str = Security(api_key_header)):
    """
    Authenticates requests using a master API key.

    Args:
        api_key (str): The API key provided in the 'X-API-Key' header.

    Raises:
        HTTPException: If the provided API key is invalid.

    Returns:
        str: The validated API key.
    """
    if api_key == MASTER_API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API Key",
    )