
FROM mcr.microsoft.com/devcontainers/python:3.11

ARG USERNAME=vscode

USER root

# Minimal tools (keep lean)
RUN apt-get update && apt-get install -y \
    git curl jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

ENV PYTHONPATH=/workspace

RUN chown -R ${USERNAME}:${USERNAME} /workspace

USER ${USERNAME}