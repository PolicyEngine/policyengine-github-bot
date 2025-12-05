"""Configuration and settings for the GitHub bot."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # GitHub App credentials
    github_app_id: int
    github_private_key: str  # PEM-encoded private key
    github_webhook_secret: str

    # Anthropic API
    anthropic_api_key: str

    # Optional: default model
    anthropic_model: str = "claude-sonnet-4-20250514"

    # Server config
    host: str = "0.0.0.0"
    port: int = 8080


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
