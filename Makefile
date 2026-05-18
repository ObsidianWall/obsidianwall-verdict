# obsidianwall-verdict/Makefile

# ObsidianWall Verdict — Development Commands
#
# Usage:
#   make install      Install dependencies
#   make test         Run full test suite
#   make lint         Run static analysis
#   make audit        Run security scan
#   make check        Run lint + audit + test
#   make build        Build distribution package
#   make docker       Build staging Docker image
#   make deps         Generate dependency graph
#   make clean        Remove build artifacts

.PHONY: install test unit integration contracts \
        lint audit check build docker deps clean \
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
		--cov-report=term-missing

integration:
	pytest tests/integration/ -v

contracts:
	pytest tests/contracts/ -v

test: unit integration contracts

coverage:
	pytest tests/ \
		--cov=engine \
		--cov=schemas \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=75
	@echo "Coverage report: htmlcov/index.html"


# =====================================================
# STATIC ANALYSIS
# =====================================================

lint:
	ruff check engine/ schemas/ audit/ cli/

audit:
	bandit -r engine/ schemas/ audit/ -ll -f txt

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
