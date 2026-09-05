"""Root endpoint.

Returns a small, stable document identifying the service and pointing at the
machine-readable entry points. It exists so that hitting the bare API host
answers "what is this and is it working?" without guessing a path — which is the
first thing an operator does during an incident (§128).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from arb_api.state import StateDep

__all__ = ["router"]

router = APIRouter(tags=["meta"])


@router.get("/", summary="Service identity and entry points")
async def root(state: StateDep) -> dict[str, Any]:
    """Describe the service and link to health, docs and the versioned API."""
    settings = state.settings
    return {
        "service": settings.service_name,
        "version": settings.app_version,
        "environment": settings.environment.value,
        "documentation": {
            "openapi": "/openapi.json",
            "swagger_ui": "/docs",
            "redoc": "/redoc",
        },
        "health": {
            "live": "/health/live",
            "ready": "/health/ready",
            "full": "/health",
        },
        "api": "/api/v1",
        # Trading safety gates are exposed here as well as on
        # /api/v1/system/info, because a deployment mistake is most often
        # discovered by curling the root of the API (§31).
        "trading": {
            "live_trading_enabled": settings.live_trading_enabled,
            "global_kill_switch_enabled": settings.global_kill_switch_enabled,
        },
    }
