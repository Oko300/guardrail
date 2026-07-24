import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
import uvicorn

from api.routes import router as api_router, limiter, _rate_limit_exceeded_handler, _check_rpc_connectivity, _check_okx_api_connectivity, APP_VERSION, APP_TITLE, APP_DESCRIPTION
from core.session import cleanup_expired_sessions
from config import PORT, SESSION_TIMEOUT_HOURS

# Initialize logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# FastAPI application lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles startup and shutdown events for the FastAPI application.
    """
    logger.info("GuardRail application starting up...")

    # Test RPC and OKX connectivity on startup
    rpc_connected = await _check_rpc_connectivity()
    okx_api_connected = await _check_okx_api_connectivity()
    logger.info(f"X Layer RPC connected: {rpc_connected}")
    logger.info(f"OKX API connected: {okx_api_connected}")

    # Start background task for session cleanup
    app.state.cleanup_task = asyncio.create_task(periodic_session_cleanup())
    logger.info("Started periodic session cleanup task.")

    yield

    logger.info("GuardRail application shutting down...")
    # Cancel background task on shutdown
    app.state.cleanup_task.cancel()
    try:
        await app.state.cleanup_task
    except asyncio.CancelledError:
        logger.info("Periodic session cleanup task cancelled.")

# Initialize FastAPI app
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://oko300.github.io", "*"],  # Allows GitHub Pages and all other origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Add SlowAPI rate limiting exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include API routes
app.include_router(api_router, prefix="/api/v1")

# Background task for session cleanup
async def periodic_session_cleanup():
    """
    Periodically cleans up expired sessions.
    """
    while True:
        await asyncio.sleep(SESSION_TIMEOUT_HOURS * 3600)  # Run every hour
        logger.info("Running expired session cleanup...")
        await cleanup_expired_sessions() # Await the async function
        logger.info("Expired session cleanup complete.")

if __name__ == "__main__":
    # This block is for local development and testing.
    # In a production environment, you might use a process manager like Gunicorn.
    logger.info(f"Starting GuardRail server on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=int(PORT))
