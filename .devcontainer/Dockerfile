
# Use modern Python (not 3.11)
FROM mcr.microsoft.com/devcontainers/python:3.13-bookworm

ARG USERNAME=obsidianwall
ARG USER_UID=1001
ARG USER_GID=$USER_UID

USER root

# Core dependencies (minimal but intentional)
RUN apt-get update && apt-get install -y \
    git curl jq \
    && rm -rf /var/lib/apt/lists/*

# Create platform user (align with golden image)
RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd --uid ${USER_UID} --gid ${USERNAME} \
    --shell /bin/bash --create-home ${USERNAME}

WORKDIR /workspace

# Copy dependency files first (layer caching)
COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy application
COPY . .

# Python path for module resolution
ENV PYTHONPATH=/workspace

# Ownership
RUN chown -R ${USERNAME}:${USERNAME} /workspace

USER ${USERNAME}