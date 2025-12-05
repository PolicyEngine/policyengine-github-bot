"""FastAPI application for PolicyEngine GitHub bot."""

import logging

from fastapi import FastAPI

from policyengine_github_bot.webhooks import router as webhook_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

app = FastAPI(
    title="PolicyEngine GitHub Bot",
    description="Responds to issues and reviews PRs on PolicyEngine repositories.",
    version="0.1.0",
)

app.include_router(webhook_router)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "service": "policyengine-github-bot"}


@app.get("/health")
async def health():
    """Health check for Cloud Run."""
    return {"status": "healthy"}
