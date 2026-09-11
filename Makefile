.PHONY: bootstrap dev dev-api dev-web worker check lint format test typecheck web-check self-scan clean

VENV := .venv
PY := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
RUFF := $(VENV)/bin/ruff
PYTEST := $(VENV)/bin/pytest

# ── Bootstrap ────────────────────────────────────────────────────────
bootstrap:
	@echo "→ Creating venv..."
	python3 -m venv --without-pip $(VENV) 2>/dev/null || python3 -m venv $(VENV)
	@if [ ! -f $(PIP) ]; then \
		echo "→ Bootstrapping pip..."; \
		curl -sS https://bootstrap.pypa.io/get-pip.py | $(PY); \
	fi
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	@echo "→ Running migrations..."
	$(VENV)/bin/alembic upgrade head 2>/dev/null || echo "⚠ Migrations not configured yet"
	@echo "✓ Bootstrap complete"

# ── Development ──────────────────────────────────────────────────────
dev: dev-api

dev-api:
	$(VENV)/bin/uvicorn apps.api.main:app --reload --port 8000

dev-web:
	npm --prefix apps/web run dev

worker:
	$(VENV)/bin/safescope worker start

# ── Quality ──────────────────────────────────────────────────────────
check: lint typecheck test web-check
	@echo "✓ All checks passed"

lint:
	$(RUFF) check packages/ apps/api/ worker/ tests/
	$(RUFF) format --check packages/ apps/api/ worker/ tests/

format:
	$(RUFF) check --fix packages/ apps/api/ worker/ tests/
	$(RUFF) format packages/ apps/api/ worker/ tests/

typecheck:
	$(PY) -m pyright packages/ apps/api/ worker/

web-check:
	npm --prefix apps/web run typecheck

test:
	$(PYTEST) -v tests/

test-policy:
	$(PYTEST) -v tests/policy/

test-scanners:
	$(PYTEST) -v tests/scanners/

# ── Self-scan (dogfooding) ───────────────────────────────────────────
self-scan:
	@echo "⚠ Self-scan not implemented yet — Phase 10"

# ── Clean ────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	rm -f *.db *.sqlite *.sqlite3
