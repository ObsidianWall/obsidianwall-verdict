
#!/bin/bash
# obsidianwall-verdict/.devcontainer/post_create.sh
#
# Runs once after the devcontainer is created.
# Verifies the environment is healthy and ready for development.
# Does NOT install tools — the Dockerfile handles that.

set -e

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ObsidianWall Verdict — Dev Environment Setup"
echo "═══════════════════════════════════════════════════════════"

# =====================================================
# PYTHON ENVIRONMENT VERIFICATION
# =====================================================

echo ""
echo "→ Python version:"
python --version

echo "→ Pip version:"
python -m pip --version

echo "→ Verifying core dependencies..."
python -c "import pydantic; print(f'  pydantic {pydantic.__version__} ✓')"
python -c "import yaml; print(f'  pyyaml ✓')"
python -c "import click; print(f'  click ✓')"
python -c "import pytest; print(f'  pytest ✓')"

# =====================================================
# PYTHONPATH VERIFICATION
# =====================================================

echo ""
echo "→ Verifying PYTHONPATH..."
python -c "
import sys
path = '/workspaces/obsidianwall-verdict'
if path in sys.path:
    print(f'  PYTHONPATH includes {path} ✓')
else:
    print(f'  WARNING: {path} not in sys.path')
    sys.exit(1)
"

# =====================================================
# ENGINE IMPORT VERIFICATION
# =====================================================

echo ""
echo "→ Verifying engine imports..."

python -c "
modules = [
    'engine.condition_evaluator',
    'engine.decision_resolver',
    'engine.policy_normalizer',
    'engine.risk_scorer',
    'engine.recommender',
    'schemas.policy_schema',
]
for module in modules:
    try:
        __import__(module)
        print(f'  {module} ✓')
    except ImportError as e:
        print(f'  {module} ✗ — {e}')
        exit(1)
"

# =====================================================
# POLICY FILES VERIFICATION
# =====================================================

echo ""
echo "→ Verifying policy files..."

for policy in policies/cost/basic_budget.yaml policies/cost/strict_budget.yaml; do
    if [ -f "$policy" ]; then
        echo "  $policy ✓"
    else
        echo "  $policy ✗ — missing"
    fi
done

# =====================================================
# MAKE TARGETS VERIFICATION
# =====================================================

echo ""
echo "→ Verifying Makefile targets..."
if [ -f "Makefile" ]; then
    echo "  Makefile ✓"
    make --dry-run test > /dev/null 2>&1 \
        && echo "  make test target ✓" \
        || echo "  make test target — check Makefile"
else
    echo "  Makefile missing"
fi

# =====================================================
# DONE
# =====================================================

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✅ Dev environment ready."
echo ""
echo "  Quick commands:"
echo "    make test       — run full test suite"
echo "    make unit       — run unit tests only"
echo "    make lint       — run ruff + bandit"
echo "    make check      — lint + audit + test"
echo "    make staging    — build + smoke test Docker image"
echo "═══════════════════════════════════════════════════════════"
echo ""