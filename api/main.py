"""AC-2035 API — the control plane tying every phase together.

Serves the graph (Cytoscape.js), the honeytoken registry, kill-switch
audit/approval, the end-to-end trigger pipeline, and a live WebSocket alert
stream the Phase 8 dashboard subscribes to.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from api import websocket
from api.models import HealthResponse
from api.routes import alerts, graph, killswitch, tokens


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Apply the Neo4j schema on startup, but never let an unreachable graph
    # stop the API from coming up — routes degrade to 500s until it's back.
    try:
        from graph.schema import apply_schema, get_driver

        driver = get_driver()
        driver.verify_connectivity()
        apply_schema(driver)
        logger.info("Neo4j schema applied")
    except Exception as e:
        logger.warning("Neo4j unavailable on startup ({}) — continuing without it", e)

    logger.info("AC-2035 API ready")
    yield
    logger.info("AC-2035 API shutting down")


app = FastAPI(title="AC-2035 API", version="1.0.0", lifespan=lifespan)

# CORS — permissive in dev; override with CORS_ORIGINS (comma-separated) in .env.
_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(graph.router)
app.include_router(alerts.router)
app.include_router(tokens.router)
app.include_router(killswitch.router)
app.include_router(websocket.router)  # /ws


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness/readiness probe."""
    return HealthResponse(status="ok")
