"""Rules Management API — FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import config
from .models import ErrorResponse
from .opa_manager import OPAManager
from .store import RulesStore

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, config.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("rules_management")

# ---------------------------------------------------------------------------
# Singletons (created once, shared across request handlers via dependency)
# ---------------------------------------------------------------------------

_store: RulesStore | None = None
_opa: OPAManager | None = None


def get_store() -> RulesStore:
    assert _store is not None, "Store not initialised"
    return _store


def get_opa() -> OPAManager:
    assert _opa is not None, "OPAManager not initialised"
    return _opa


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _store, _opa

    logger.info("Starting Rules Management API")
    _store = RulesStore(config.rules_store_path)
    _opa = OPAManager(opa_url=config.opa_url, timeout=config.opa_timeout)

    # Push current rules_config to OPA so it starts with the persisted state
    try:
        rules_config = _store.build_rules_config()
        await _opa.push_rules_config(rules_config)
        logger.info("rules_config pushed to OPA on startup")
    except Exception as exc:
        logger.warning(f"OPA not reachable on startup (will retry on requests): {exc}")

    yield

    logger.info("Shutting down Rules Management API")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Thebe Protocol — Rules Management API",
    description=(
        "Control plane for surfacing, toggling, and dynamically creating "
        "Zero-Trust Guardian security rules."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(f"Unhandled error on {request.method} {request.url.path}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_error",
            message="An unexpected error occurred",
        ).model_dump(),
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from .routers import custom_rules, meta, system_rules  # noqa: E402

app.include_router(system_rules.router)
app.include_router(custom_rules.router)
app.include_router(meta.router)

# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def root() -> dict:
    return {
        "service": "rules-management",
        "version": "1.0.0",
        "docs": "/docs",
    }


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.rules_management.main:app",
        host=config.host,
        port=config.port,
        reload=True,
        log_config=None,
    )
