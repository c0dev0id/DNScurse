"""Pytest configuration for DNScurse tests."""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "network: marks tests that require network access (deselect with '-m \"not network\"')",
    )
