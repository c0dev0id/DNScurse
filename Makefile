VENV   := .venv
PYTHON := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip3

.PHONY: build run test clean install

$(VENV):
	python3 -m venv $(VENV)

build: $(VENV)
	$(PIP) install -e ".[dev]"

run: build
	$(PYTHON) -m dnscurse $(ARGS)

test: build
	$(PYTHON) -m pytest tests/ -m "not network"

install:
	pipx install .

clean:
	rm -rf $(VENV) .pytest_cache *.egg-info
	find . -name __pycache__ -exec rm -rf {} +
