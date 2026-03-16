VENV   := .venv
PYTHON := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip3

.PHONY: build run test clean install uninstall

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

uninstall:
	pipx uninstall dnscurse

clean:
	rm -rf $(VENV) .pytest_cache *.egg-info
	find . -name __pycache__ -exec rm -rf {} +

