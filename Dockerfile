FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# Install dependencies
RUN uv sync --frozen --no-dev

# Expose port
EXPOSE 8080

# Run the application
CMD ["uv", "run", "uvicorn", "policyengine_github_bot.main:app", "--host", "0.0.0.0", "--port", "8080"]
