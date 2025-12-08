"""Tests for GitHub authentication and authorization."""

from unittest.mock import AsyncMock, patch

import pytest

from policyengine_github_bot.github_auth import is_user_authorized_async


class TestIsUserAuthorizedAsync:
    @pytest.mark.asyncio
    async def test_authorized_user_returns_true(self):
        """Test that a team member is authorized."""
        mock_response = {
            "data": {
                "organization": {
                    "team": {
                        "members": {
                            "nodes": [{"login": "nikhilwoodruff"}]
                        }
                    }
                }
            }
        }

        with patch(
            "policyengine_github_bot.github_auth.graphql_request",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await is_user_authorized_async(12345, "nikhilwoodruff")
            assert result is True

    @pytest.mark.asyncio
    async def test_unauthorized_user_returns_false(self):
        """Test that a non-team member is not authorized."""
        mock_response = {
            "data": {
                "organization": {
                    "team": {
                        "members": {
                            "nodes": []  # User not in results
                        }
                    }
                }
            }
        }

        with patch(
            "policyengine_github_bot.github_auth.graphql_request",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await is_user_authorized_async(12345, "randomuser")
            assert result is False

    @pytest.mark.asyncio
    async def test_case_insensitive_username_match(self):
        """Test that username matching is case-insensitive."""
        mock_response = {
            "data": {
                "organization": {
                    "team": {
                        "members": {
                            "nodes": [{"login": "NikhilWoodruff"}]
                        }
                    }
                }
            }
        }

        with patch(
            "policyengine_github_bot.github_auth.graphql_request",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await is_user_authorized_async(12345, "nikhilwoodruff")
            assert result is True

    @pytest.mark.asyncio
    async def test_null_team_returns_false(self):
        """Test that null team data (no permission) returns false."""
        mock_response = {
            "data": {
                "organization": {
                    "team": None  # No permission to access team
                }
            }
        }

        with patch(
            "policyengine_github_bot.github_auth.graphql_request",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await is_user_authorized_async(12345, "nikhilwoodruff")
            assert result is False

    @pytest.mark.asyncio
    async def test_graphql_error_returns_false(self):
        """Test that GraphQL errors fail closed (return false)."""
        with patch(
            "policyengine_github_bot.github_auth.graphql_request",
            new_callable=AsyncMock,
            side_effect=Exception("GraphQL error"),
        ):
            result = await is_user_authorized_async(12345, "nikhilwoodruff")
            assert result is False

    @pytest.mark.asyncio
    async def test_graphql_request_called_with_correct_params(self):
        """Test that GraphQL request is called with correct parameters."""
        mock_response = {
            "data": {
                "organization": {
                    "team": {
                        "members": {"nodes": []}
                    }
                }
            }
        }

        with patch(
            "policyengine_github_bot.github_auth.graphql_request",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_graphql:
            await is_user_authorized_async(12345, "testuser")

            mock_graphql.assert_called_once()
            call_args = mock_graphql.call_args
            assert call_args[0][0] == 12345  # installation_id
            assert "organization" in call_args[0][1]  # query contains organization
            assert call_args[0][2] == {
                "org": "PolicyEngine",
                "team": "core-developers",
                "username": "testuser",
            }
