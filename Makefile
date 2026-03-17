VENV   := .venv
PYTHON := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip3
PYTEST := $(VENV)/bin/pytest

.PHONY: all build run test test-lib test-cli test-net clean install uninstall man

$(VENV):
	python3 -m venv $(VENV)

build: $(VENV)
	$(PIP) install -e ".[dev]"

run: build
	$(PYTHON) -m dnscurse $(ARGS)

test: build
	$(PYTEST) -m "not network"

test-lib: build
	$(PYTEST) -m "not network and not cli"

test-cli: build
	$(PYTEST) -m "cli"

test-net: build
	$(PYTEST) -m "network"

install:
	pipx install .

uninstall:
	pipx uninstall dnscurse

docs/dnscurse.1.txt: man/dnscurse.1
	mandoc -T ascii man/dnscurse.1 | col -bx > docs/dnscurse.1.txt

docs/dnscurse.3.txt: man/dnscurse.3
	mandoc -T ascii man/dnscurse.3 | col -bx > docs/dnscurse.3.txt

man: docs/dnscurse.1.txt docs/dnscurse.3.txt
	mandoc -a man/dnscurse.1

clean:
	rm -rf $(VENV) .pytest_cache *.egg-info
	find . -name __pycache__ -exec rm -rf {} +

