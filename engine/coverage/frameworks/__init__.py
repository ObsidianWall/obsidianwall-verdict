# engine/coverage/frameworks/__init__.py
#
# Compliance framework control mappings for the coverage
# engine. Each framework maps policy condition keywords
# to specific regulatory or standards-based controls.
#
# Available frameworks:
#   HIPAA_CONTROLS         → HIPAA Security Rule
#   SOC2_CONTROLS          → SOC 2 Trust Service Criteria
#   CIS_CONTROLS           → CIS Controls v8
#   NIST_AI_RMF_CONTROLS   → NIST AI Risk Management Framework
#
# Adding a new framework:
#   1. Create frameworks/<name>.py following the same
#      dict[str, dict[str, Any]] structure
#   2. Import and add to FRAMEWORK_REGISTRY below
#   3. No changes needed to coverage_engine.py

from engine.coverage.frameworks.cis_controls import CIS_CONTROLS
from engine.coverage.frameworks.hipaa import HIPAA_CONTROLS
from engine.coverage.frameworks.nist_ai_rmf import NIST_AI_RMF_CONTROLS
from engine.coverage.frameworks.soc2 import SOC2_CONTROLS

FRAMEWORK_REGISTRY: dict[str, dict] = {
    "hipaa": HIPAA_CONTROLS,
    "soc2": SOC2_CONTROLS,
    "cis": CIS_CONTROLS,
    "nist_ai_rmf": NIST_AI_RMF_CONTROLS,
}

__all__ = [
    "HIPAA_CONTROLS",
    "SOC2_CONTROLS",
    "CIS_CONTROLS",
    "NIST_AI_RMF_CONTROLS",
    "FRAMEWORK_REGISTRY",
]
