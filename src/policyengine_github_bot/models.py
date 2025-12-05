"""Pydantic models for GitHub webhook payloads."""

from pydantic import BaseModel, Field


class GitHubUser(BaseModel):
    """GitHub user information."""

    login: str
    id: int


class GitHubRepository(BaseModel):
    """GitHub repository information."""

    id: int
    name: str
    full_name: str
    private: bool = False


class GitHubIssue(BaseModel):
    """GitHub issue information."""

    id: int
    number: int
    title: str
    body: str | None = None
    state: str = "open"
    user: GitHubUser


class GitHubInstallation(BaseModel):
    """GitHub App installation information."""

    id: int


class GitHubComment(BaseModel):
    """GitHub comment information."""

    id: int
    body: str
    user: GitHubUser


class IssueWebhookPayload(BaseModel):
    """Payload for issue webhook events."""

    action: str
    issue: GitHubIssue
    repository: GitHubRepository
    installation: GitHubInstallation | None = None
    sender: GitHubUser


class IssueCommentWebhookPayload(BaseModel):
    """Payload for issue_comment webhook events."""

    action: str
    issue: GitHubIssue
    comment: GitHubComment
    repository: GitHubRepository
    installation: GitHubInstallation | None = None
    sender: GitHubUser


class PingWebhookPayload(BaseModel):
    """Payload for ping webhook events."""

    zen: str = ""
    hook_id: int = 0


class IssueResponse(BaseModel):
    """Response generated for an issue."""

    content: str = Field(description="The response text to post as a comment")
