# Testing PyLocalDNS Flask Web Interface

This document describes the test suite for the PyLocalDNS Flask web interface.

## Overview

The test suite verifies that the Flask routes, HTMX integration, and port scanning functionality in PyLocalDNS work correctly.

## Test Files

- `test_flask_routes.py`: Tests for Flask routes and basic web UI functionality
- `test_htmx_integration.py`: Tests for HTMX integration for dynamic content updates
- `test_port_scanning.py`: Tests for port scanning functionality and display

## Running Tests

To run all tests:

```bash
./run_tests.sh
```

To run an individual test file:

```bash
python -m unittest tests/test_flask_routes.py
```

## Test Requirements

- Flask (required for the web UI)
- unittest (part of the Python standard library)
- Coverage.py (optional, for test coverage reports)

If you don't have coverage installed, you can install it with:

```bash
pip install coverage
```

## Test Coverage

The tests cover the following functionality:

### Flask Routes Tests

- Home page rendering
- Dashboard content for HTMX updates
- Add entry form and submission
- Edit entry form and submission
- Delete entry functionality
- Scan network page and functionality
- Settings page and configuration
- API health check

### HTMX Integration Tests

- HTMX library inclusion in HTML
- Dashboard content partial updates
- Port scanning with HTMX
- API refresh endpoint
- HTMX attributes in HTML
- Scan ports button functionality
- Add entry with HTMX refresh

### Port Scanning Tests

- Port formatting utility function
- Port display in dashboard
- Scan ports functionality
- Port display in scan results
- Port categorization
- Port database integration

## Mock Objects

The tests use mock objects to simulate:

- Network server
- Port database
- Network scanning
- Port scanning

This allows testing without requiring actual network connectivity or port scanning capabilities.

## Writing Additional Tests

When adding new functionality to the Flask web interface, you should create corresponding tests. Follow these guidelines:

1. Choose the appropriate test file based on what you're testing
2. Use the same setup pattern with a temporary hosts file
3. Mock external dependencies
4. Test both GET and POST requests for routes
5. Verify both the response status and the content

## Test Structure

Each test file follows the same basic structure:

1. Imports and setup
2. `setUp()` method to create a temporary environment
3. `tearDown()` method to clean up
4. Individual test methods for specific functionality
5. Main block to run the tests directly

## Continuous Integration

These tests can be integrated into a CI/CD pipeline by running:

```bash
python -m unittest discover -s tests
```

For coverage reporting in CI:

```bash
coverage run -m unittest discover -s tests
coverage report -m
coverage xml  # For integration with tools like Codecov
```
