"""GitHub App authentication utilities."""

import time

import jwt
from github import Auth, Github, GithubIntegration

from policyengine_github_bot.config import get_settings


def get_jwt_token() -> str:
    """Generate a JWT for GitHub App authentication."""
    settings = get_settings()

    now = int(time.time())
    payload = {
        "iat": now - 60,  # issued at time, 60s in the past to allow for clock drift
        "exp": now + (10 * 60),  # expiration time (10 minute maximum)
        "iss": settings.github_app_id,
    }

    return jwt.encode(payload, settings.github_private_key, algorithm="RS256")


def get_github_client(installation_id: int) -> Github:
    """Get a GitHub client authenticated as an installation."""
    settings = get_settings()

    auth = Auth.AppAuth(settings.github_app_id, settings.github_private_key)
    gi = GithubIntegration(auth=auth)
    installation_auth = gi.get_access_token(installation_id)

    return Github(auth=Auth.Token(installation_auth.token))


def get_installation_id(owner: str, repo: str) -> int:
    """Get the installation ID for a repository."""
    settings = get_settings()

    auth = Auth.AppAuth(settings.github_app_id, settings.github_private_key)
    gi = GithubIntegration(auth=auth)

    installation = gi.get_repo_installation(owner, repo)
    return installation.id
