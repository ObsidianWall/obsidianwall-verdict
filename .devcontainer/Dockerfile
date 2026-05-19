FROM mcr.microsoft.com/devcontainers/python:dev-3.13-bookworm

ARG USERNAME=obsidianwall
ARG USER_UID=1001
ARG USER_GID=1001

USER root

RUN apt-get update && apt-get install -y \
        --no-install-recommends \
        sudo git-lfs coreutils curl gnupg2 make jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid ${USER_GID} ${USERNAME} \
    && useradd \
        --uid ${USER_UID} \
        --gid ${USERNAME} \
        --shell /bin/bash \
        --create-home ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" \
        > /etc/sudoers.d/90-${USERNAME} \
    && chmod 0440 /etc/sudoers.d/90-${USERNAME}

RUN git lfs install --system

COPY requirements.txt /tmp/verdict-requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/verdict-requirements.txt \
    && rm /tmp/verdict-requirements.txt

RUN pip install --no-cache-dir pytest pytest-cov ruff bandit

ENV PYTHONPATH=/workspaces/obsidianwall-verdict \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OW_VERDICT_ENV=development \
    OW_LOG_LEVEL=DEBUG \
    OW_LOG_FORMAT=text \
    OW_POLICY_DIR=/workspaces/obsidianwall-verdict/policies \
    PATH="/home/${USERNAME}/.local/bin:/usr/local/bin:/usr/bin:/bin:${PATH}"

WORKDIR /workspaces/obsidianwall-verdict

USER ${USERNAME}
