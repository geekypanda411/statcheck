PYTHON ?= .venv/bin/python

.PHONY: install test lint format typecheck smoke compileall

install:
	$(PYTHON) -m pip install -e ".[dev]"

compileall:
	$(PYTHON) -m compileall -q main.py src

test: compileall
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

typecheck:
	$(PYTHON) -m mypy src main.py

smoke:
	$(PYTHON) main.py /bin/true --format elf --report json \
		--config tools_config.json.example --output-dir /tmp/statcheck-smoke
