# obsidianwall-verdict/Dockerfile
#
# ObsidianWall Verdict — Runtime Image
# Staging and production deployment.
#
# This is NOT the devcontainer image.
# For development, use .devcontainer/Dockerfile instead.
#
# Uses python:3.13-slim — not the devcontainer base.
# The devcontainer base includes VS Code server,
# git tooling, and dev utilities that add ~800MB
# of unnecessary weight to a runtime image.
#
# Build:
#   docker build -t obsidianwall-verdict:staging .
#
# Run:
#   docker run --rm \
#     -v $(pwd)/policies:/app/policies \
#     -v $(pwd)/samples:/app/samples \
#     obsidianwall-verdict:staging \
#     evaluate \
#     --plan samples/terraform_plan.json \
#     --policy policies/cost/basic_budget.yaml \
#     --role engineer

FROM python:3.13-slim

# =====================================================
# BUILD ARGS
# =====================================================

ARG USERNAME=verdict
ARG USER_UID=1001
ARG USER_GID=1001
ARG APP_VERSION=0.2.0

# =====================================================
# ENVIRONMENT
# =====================================================

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    OW_VERDICT_ENV=staging \
    OW_LOG_LEVEL=INFO \
    OW_LOG_FORMAT=json

# =====================================================
# SYSTEM DEPENDENCIES
# Minimal — only what the runtime needs.
# No git, no curl, no dev tools.
# =====================================================

RUN apt-get update && apt-get install -y \
        --no-install-recommends \
        jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# =====================================================
# NON-ROOT USER
# A governance engine must never run as root.
# =====================================================

RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd \
        --uid ${USER_UID} \
        --gid ${USERNAME} \
        --shell /bin/bash \
        --no-create-home \
        ${USERNAME}

# =====================================================
# APPLICATION
# =====================================================

WORKDIR /app

# ---------------------------------------------------
# Dependencies first — layer caching.
# Only requirements.txt changes invalidate this layer,
# not application code changes.
# ---------------------------------------------------

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------
# Application source — only runtime modules.
# Tests, docs, and dev files excluded via .dockerignore.
# ---------------------------------------------------

COPY engine/      ./engine/
COPY schemas/     ./schemas/
COPY audit/       ./audit/
COPY cli/         ./cli/
COPY policies/    ./policies/

# ---------------------------------------------------
# Ownership — non-root user owns the app directory
# ---------------------------------------------------

RUN chown -R ${USERNAME}:${USERNAME} /app

# =====================================================
# SWITCH TO NON-ROOT
# =====================================================

USER ${USERNAME}

# =====================================================
# HEALTHCHECK
# Verifies the CLI entry point responds correctly.
# =====================================================

HEALTHCHECK \
    --interval=30s \
    --timeout=10s \
    --start-period=5s \
    --retries=3 \
    CMD python -m cli.main --help > /dev/null || exit 1

# =====================================================
# LABELS — OCI standard metadata
# =====================================================

LABEL \
    org.opencontainers.image.title="ObsidianWall Verdict" \
    org.opencontainers.image.description="Deterministic pre-deployment infrastructure governance engine." \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.licenses="BSL-1.1" \
    org.opencontainers.image.source="https://github.com/ObsidianWall/obsidianwall-verdict"

# =====================================================
# ENTRYPOINT
# =====================================================

ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]
