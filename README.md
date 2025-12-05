# PolicyEngine GitHub Bot

GitHub App that automatically responds to issues and reviews PRs on PolicyEngine repositories using Claude.

## Setup

1. Create a GitHub App with the required permissions (issues: read/write)
2. Copy `.env.example` to `.env` and fill in your credentials
3. Run locally: `uv run uvicorn policyengine_github_bot.main:app --reload`

## Deployment

Deploy to Cloud Run:

```bash
gcloud run deploy policyengine-github-bot \
  --source . \
  --set-env-vars "GITHUB_APP_ID=...,ANTHROPIC_API_KEY=..." \
  --set-secrets "GITHUB_PRIVATE_KEY=github-private-key:latest,GITHUB_WEBHOOK_SECRET=github-webhook-secret:latest"
```
