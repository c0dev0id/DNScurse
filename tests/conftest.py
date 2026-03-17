"""Pytest configuration for DNScurse tests."""



def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "network: marks tests that require network access (deselect with '-m \"not network\"')",
    )
    config.addinivalue_line(
        "markers",
        "cli: marks tests that exercise the CLI entry point (deselect with '-m \"not cli\"')",
    )
