"""FastAPI application for PolicyEngine GitHub bot."""

import logfire
from fastapi import FastAPI

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.webhooks import router as webhook_router

settings = get_settings()

logfire.configure(
    token=settings.logfire_token,
    environment=settings.logfire_env,
    service_name="policyengine-github-bot",
)

app = FastAPI(
    title="PolicyEngine GitHub Bot",
    description="Responds to issues and reviews PRs on PolicyEngine repositories.",
    version="0.1.0",
)

logfire.instrument_fastapi(app)

app.include_router(webhook_router)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "service": "policyengine-github-bot"}


@app.get("/health")
async def health():
    """Health check for Cloud Run."""
    return {"status": "healthy"}
