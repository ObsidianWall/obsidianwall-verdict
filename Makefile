# obsidianwall-verdict/Makefile

# ObsidianWall Verdict — Development Commands
#
# Usage:
#   make install            Install dependencies
#   make test               Run fast development suite
#   make test-all           Run complete suite, including distribution
#   make test-distribution  Run slow distribution regression suite
#   make unit               Run unit tests only
#   make integration        Run integration tests only
#   make contracts          Run contract tests only
#   make lint               Run static analysis
#   make audit              Run security scan
#   make check              Run lint + audit + fast tests
#   make coverage           Run fast suite with coverage
#   make build              Build distribution package
#   make docker             Build staging Docker image
#   make staging            Build + smoke test staging image
#   make deps               Generate dependency graph
#   make depcheck           Check module dependencies
#   make clean              Remove build artifacts

.PHONY: install test test-all test-distribution \
        unit integration contracts \
        lint audit check build docker deps depcheck clean \
        coverage staging


# =====================================================
# INSTALL
# =====================================================

install:
	pip install -e ".[dev]"


# =====================================================
# TESTING
# =====================================================

unit:
	pytest tests/unit/ -v \
		--cov=engine \
		--cov=schemas \
		--cov=authority \
		--cov-report=term-missing

integration:
	pytest tests/integration/ -v

contracts:
	pytest tests/contracts/ -v

# Routine development loop.
# Runs every discovered test except those deliberately
# classified as slow.
test:
	pytest tests/ -m "not slow" -v

# Complete repository verification.
# "Complete" always means all tests, including slow
# distribution/packaging regression tests.
test-all:
	pytest tests/ -v

# Distribution assurance only.
# Builds, installs, and validates a real wheel.
test-distribution:
	pytest tests/distribution/ -m slow -v

# Coverage belongs to the routine development loop.
# Distribution tests verify artifact behavior rather than
# useful source-coverage semantics, so they are excluded.

# Source coverage policy:
# - 90% is the project-wide minimum coverage gate.
# - The same threshold is enforced locally and in routine CI.
# - Slow distribution tests are excluded because they validate
#   built-artifact behavior rather than source-coverage semantics.

coverage:
	pytest tests/ -m "not slow" \
		--cov=engine \
		--cov=cli \
		--cov=schemas \
		--cov=audit \
		--cov=notifications \
		--cov=telemetry \
		--cov=context \
		--cov=render \
		--cov=authority \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=90
	@echo "Coverage report: htmlcov/index.html"


# =====================================================
# STATIC ANALYSIS
# =====================================================

lint:
	ruff check engine/ schemas/ audit/ cli/ authority/

audit:
	bandit -r engine/ schemas/ audit/ authority/ -ll -f txt

# test is deliberately the fast routine suite,
# so check remains suitable for the development loop.
check: lint audit test


# =====================================================
# BUILD
# =====================================================

build:
	python -m build
	@echo "Distribution: dist/"


# =====================================================
# DOCKER / STAGING
# =====================================================

docker:
	docker build -t obsidianwall-verdict:staging .
	@echo "Image: obsidianwall-verdict:staging"

staging: docker
	@echo "Running staging smoke test..."
	docker run --rm \
		-v $$(pwd)/policies:/app/policies \
		-v $$(pwd)/samples:/app/samples \
		obsidianwall-verdict:staging \
		evaluate \
		--plan samples/terraform_plan.json \
		--policy policies/cost/basic_budget.yaml \
		--role engineer


# =====================================================
# DEPENDENCY GRAPH
# =====================================================

deps:
	@echo "Generating dependency graph..."
	pydeps engine/ --noshow -o docs/deps.svg
	pyreverse -o png -p ObsidianWall engine/ -d docs/
	@echo "Graphs: docs/deps.svg, docs/classes_ObsidianWall.png"

depcheck:
	python -m importlab engine/ --recursive


# =====================================================
# CLEAN
# =====================================================

clean:
	rm -rf dist/ build/ *.egg-info
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "Cleaned."