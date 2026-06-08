# cli/commands/sentinel/__init__.py
#
# Purpose:
# Exposes sentinel_app for registration in cli/main.py.
#
# Architecture boundary:
# This folder is the Option C boundary for Sentinel.
# All Sentinel commands live here, isolated from Verdict
# commands. When Sentinel warrants its own package
# (obsidianwall-sentinel), this folder moves cleanly
# without touching other modules.
#
# Command pattern:
#   verdict sentinel scan    ← primary command
#   verdict sentinel report  ← future
#   verdict sentinel history ← future

from cli.commands.sentinel.scan import sentinel_app

__all__ = ["sentinel_app"]
