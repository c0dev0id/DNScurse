VENV   := .venv
PYTHON := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip3
PYTEST := $(VENV)/bin/pytest

.PHONY: all build run test test-net clean install uninstall man

$(VENV):
	python3 -m venv $(VENV)

build: $(VENV)
	$(PIP) install -e ".[dev]"

run: build
	$(PYTHON) -m dnscurse $(ARGS)

test: build
	$(PYTEST) -m "not network"

test-net: build
	$(PYTEST) -m "network"

install:
	pipx install .

uninstall:
	pipx uninstall dnscurse

man:
	mandoc -a man/dnscurse.1

clean:
	rm -rf $(VENV) .pytest_cache *.egg-info
	find . -name __pycache__ -exec rm -rf {} +

