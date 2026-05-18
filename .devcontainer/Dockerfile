
# obsidianwall-verdict/.devcontainer/Dockerfile
#
# ObsidianWall Verdict — Development Container
#
# Inherits FROM the ObsidianWall golden CI/CD image.
# Only adds verdict-specific Python dependencies.
# All base setup (user, Docker CLI, Git LFS, core tools)
# comes from the golden image — DRY by design.
#
# Prerequisites:
# The golden image must be built and pushed to:
# ghcr.io/obsidianwall/cicd-golden:latest
#
# Build golden image first:
#   cd obsidianwall-cicd-pipeline
#   docker build -t ghcr.io/obsidianwall/cicd-golden:latest \
#     .devcontainer/
#   docker push ghcr.io/obsidianwall/cicd-golden:latest

FROM ghcr.io/obsidianwall/cicd-golden:latest

# =====================================================
# VERDICT-SPECIFIC SETUP
# Everything below this line is verdict-only.
# The golden image handles everything above.
# =====================================================

ARG USERNAME=obsidianwall

USER root

# ---------------------------------------------------
# Verdict Python dependencies
# Installed into the system path as root so they
# are available to the obsidianwall user without
# user-local install path complications.
# ---------------------------------------------------

COPY requirements.txt /tmp/verdict-requirements.txt

RUN pip install --no-cache-dir \
    -r /tmp/verdict-requirements.txt \
    && rm /tmp/verdict-requirements.txt

# ---------------------------------------------------
# Development-only dependencies
# (testing, linting, coverage — not in runtime image)
# ---------------------------------------------------

RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    ruff \
    bandit \
    pydeps \
    pylint

# ---------------------------------------------------
# Verdict environment
# ---------------------------------------------------

ENV PYTHONPATH=/workspaces/obsidianwall-verdict \
    OW_VERDICT_ENV=development \
    OW_LOG_LEVEL=DEBUG \
    OW_LOG_FORMAT=text \
    OW_POLICY_DIR=/workspaces/obsidianwall-verdict/policies

# ---------------------------------------------------
# Working directory
# ---------------------------------------------------

WORKDIR /workspaces/obsidianwall-verdict

USER ${USERNAME}
