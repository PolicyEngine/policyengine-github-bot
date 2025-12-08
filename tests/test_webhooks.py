"""Tests for webhook handlers."""

import pytest

from policyengine_github_bot.webhooks import (
    format_conversation_context,
    get_conversation_context,
)


class TestFormatConversationContext:
    def test_empty_conversation(self):
        """Test formatting empty conversation."""
        result = format_conversation_context([])
        assert result == ""

    def test_single_comment(self):
        """Test formatting single comment."""
        conversation = [
            {"author": "nikhilwoodruff", "body": "Can you fix the bug?", "is_bot": False}
        ]
        result = format_conversation_context(conversation)
        assert result == "@nikhilwoodruff:\nCan you fix the bug?"

    def test_multiple_comments(self):
        """Test formatting multiple comments."""
        conversation = [
            {"author": "nikhilwoodruff", "body": "Can you fix the bug?", "is_bot": False},
            {"author": "policyengine-auto", "body": "Looking into it...", "is_bot": True},
            {"author": "nikhilwoodruff", "body": "Any update?", "is_bot": False},
        ]
        result = format_conversation_context(conversation)

        assert "@nikhilwoodruff:\nCan you fix the bug?" in result
        assert "@policyengine-auto:\nLooking into it..." in result
        assert "@nikhilwoodruff:\nAny update?" in result
        assert result.count("---") == 2  # Two separators between three comments

    def test_multiline_comment(self):
        """Test formatting comment with multiple lines."""
        conversation = [
            {
                "author": "testuser",
                "body": "Line 1\nLine 2\nLine 3",
                "is_bot": False,
            }
        ]
        result = format_conversation_context(conversation)
        assert result == "@testuser:\nLine 1\nLine 2\nLine 3"

    def test_none_handling(self):
        """Test that None is handled (should not crash)."""
        # This shouldn't happen in practice, but let's be defensive
        result = format_conversation_context(None)  # type: ignore
        assert result == ""
