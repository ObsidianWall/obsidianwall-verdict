# engine/coverage/__init__.py
#
# Compliance coverage analysis package.
#
# Maps policy conditions to compliance framework controls
# using pattern matching on condition identifiers,
# expressions, and descriptions.
#
# Primary interface:
#   from engine.coverage.coverage_engine import analyze_coverage
#
# Supported frameworks:
#   "hipaa"       → HIPAA Security Rule
#   "soc2"        → SOC 2 Trust Service Criteria
#   "cis"         → CIS Controls v8
#   "nist_ai_rmf" → NIST AI Risk Management Framework
#
# Adding a new framework:
#   1. Create engine/coverage/frameworks/<name>.py
#   2. Add to FRAMEWORK_REGISTRY in frameworks/__init__.py
#   3. No changes needed to coverage_engine.py

from engine.coverage.coverage_engine import analyze_coverage

__all__ = ["analyze_coverage"]
