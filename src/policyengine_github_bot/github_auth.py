"""GitHub App authentication utilities."""

import time

import httpx
import jwt
import logfire
from github import Auth, Github, GithubIntegration

from policyengine_github_bot.config import get_settings

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


def get_private_key() -> str:
    """Get the private key with newlines properly converted."""
    settings = get_settings()
    return settings.github_private_key.replace("\\n", "\n")


def get_jwt_token() -> str:
    """Generate a JWT for GitHub App authentication."""
    settings = get_settings()

    now = int(time.time())
    payload = {
        "iat": now - 60,  # issued at time, 60s in the past to allow for clock drift
        "exp": now + (10 * 60),  # expiration time (10 minute maximum)
        "iss": settings.github_app_id,
    }

    return jwt.encode(payload, get_private_key(), algorithm="RS256")


def get_github_client(installation_id: int) -> Github:
    """Get a GitHub client authenticated as an installation."""
    settings = get_settings()

    auth = Auth.AppAuth(settings.github_app_id, get_private_key())
    gi = GithubIntegration(auth=auth)
    installation_auth = gi.get_access_token(installation_id)

    return Github(auth=Auth.Token(installation_auth.token))


def get_installation_id(owner: str, repo: str) -> int:
    """Get the installation ID for a repository."""
    settings = get_settings()

    auth = Auth.AppAuth(settings.github_app_id, get_private_key())
    gi = GithubIntegration(auth=auth)

    installation = gi.get_repo_installation(owner, repo)
    return installation.id


def get_installation_token(installation_id: int) -> str:
    """Get an installation access token for API calls."""
    settings = get_settings()

    auth = Auth.AppAuth(settings.github_app_id, get_private_key())
    gi = GithubIntegration(auth=auth)
    installation_auth = gi.get_access_token(installation_id)

    return installation_auth.token


async def graphql_request(
    installation_id: int,
    query: str,
    variables: dict | None = None,
) -> dict:
    """Make a GraphQL request to GitHub API."""
    token = get_installation_token(installation_id)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            GITHUB_GRAPHQL_URL,
            json={"query": query, "variables": variables or {}},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        return response.json()


async def get_review_threads(
    installation_id: int,
    owner: str,
    repo: str,
    pr_number: int,
) -> list[dict]:
    """Get all review threads for a PR via GraphQL."""
    query = """
    query($owner: String!, $repo: String!, $pr_number: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $pr_number) {
          reviewThreads(first: 100) {
            nodes {
              id
              isResolved
              comments(first: 1) {
                nodes {
                  author {
                    login
                  }
                  body
                }
              }
            }
          }
        }
      }
    }
    """

    result = await graphql_request(
        installation_id,
        query,
        {"owner": owner, "repo": repo, "pr_number": pr_number},
    )

    threads = (
        result.get("data", {})
        .get("repository", {})
        .get("pullRequest", {})
        .get("reviewThreads", {})
        .get("nodes", [])
    )

    return threads


async def resolve_review_thread(installation_id: int, thread_id: str) -> bool:
    """Resolve a review thread via GraphQL."""
    mutation = """
    mutation($thread_id: ID!) {
      resolveReviewThread(input: {threadId: $thread_id}) {
        thread {
          id
          isResolved
        }
      }
    }
    """

    try:
        result = await graphql_request(
            installation_id,
            mutation,
            {"thread_id": thread_id},
        )

        resolved = (
            result.get("data", {})
            .get("resolveReviewThread", {})
            .get("thread", {})
            .get("isResolved", False)
        )

        if resolved:
            logfire.info(f"[graphql] resolved thread {thread_id[:8]}...")
        return resolved
    except Exception as e:
        logfire.error(f"[graphql] failed to resolve thread {thread_id[:8]}...: {e}")
        return False
