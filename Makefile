VENV   := .venv
PYTHON := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip3
PYTEST := $(VENV)/bin/pytest

.PHONY: all build run test test-net lint install uninstall man clean

# Default: install release version into venv (no dev/test dependencies)
all: $(VENV)
	$(PIP) install -e .

install:
	pipx install .

uninstall:
	pipx uninstall dnscurse

# Development targets

build: $(VENV)
	$(PIP) install -e ".[dev]"

run: build
	$(PYTHON) -m dnscurse $(ARGS)

test: build
	$(PYTEST) -m "not network"

test-net: build
	$(PYTEST) -m "network"

lint: build
	$(VENV)/bin/ruff check dnscurse/ tests/

man: docs/dnscurse.1.txt docs/dnscurse.3.txt
	mandoc -a man/dnscurse.1

clean:
	rm -rf $(VENV) .pytest_cache *.egg-info
	find . -name __pycache__ -exec rm -rf {} +

# -- internal targets --

$(VENV):
	python3 -m venv $(VENV)

docs/dnscurse.1.txt: man/dnscurse.1
	mandoc -T ascii man/dnscurse.1 | col -bx > docs/dnscurse.1.txt

docs/dnscurse.3.txt: man/dnscurse.3
	mandoc -T ascii man/dnscurse.3 | col -bx > docs/dnscurse.3.txt
