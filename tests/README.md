# PyLocalDNS Tests

This directory contains tests for the PyLocalDNS project. These tests cover various aspects of the system including the IP preallocation feature, DNS server, DHCP server, and the DNS API functionality.

## Test Overview

The tests are organized as follows:

### IP Preallocation Tests

- **test_ip_preallocation.py**: Comprehensive unittest-based test suite for the IP preallocation feature.
- **test_preallocation_simple.py**: A simpler, focused test for the IP preallocation feature.
- **test_debug.py**: A debug script for manual testing and development.

### API Tests

- **test_api.py**: Unit tests for the DNS API feature, including:
  - API endpoint functionality
  - API client functionality
  - API integration with the network server

## Running the Tests

You can run individual test files or use the provided shell scripts to run groups of tests:

### Running All Tests

```bash
# From the tests directory
./run_tests.sh

# From the project root
./tests/run_tests.sh
```

### Running Specific Test Groups

```bash
# Run only the IP preallocation tests
./run_simple_test.sh

# Run only the API tests
./run_api_tests.sh
```

### Running Individual Test Files

```bash
# Run a specific test file
python3 test_api.py
python3 test_ip_preallocation.py
python3 test_preallocation_simple.py
```

## Test Environment

The tests use Python's unittest framework and are designed to run in isolation, creating temporary files and running test servers on non-standard ports to avoid conflicts with any running instances of the actual server.

### Test Setup

Most tests follow this pattern:

1. Create a temporary hosts file with test data
2. Initialize a test instance of the HostsFile class
3. Mock necessary network functions to control test behavior
4. Run the tests
5. Clean up temporary files and resources

### Mocked Components

To ensure tests are reproducible and don't depend on actual network state, the following components are typically mocked:

- Network connectivity checks
- ARP table lookups
- Port scanning
- Subprocess execution

## Adding New Tests

When adding new tests, follow these guidelines:

1. For a new feature, create a new test file named `test_feature_name.py`
2. Import necessary modules from the parent directory
3. Use Python's unittest framework
4. Mock external dependencies
5. Clean up all resources in the tearDown method
6. Add your test to the appropriate run script

## API Test Structure

The API tests check:

1. **Basic Functionality**: All API endpoints work correctly
2. **Error Handling**: Properly handles invalid input
3. **Authentication**: Token-based authentication works correctly
4. **Integration**: Works correctly with the network server

## Troubleshooting

If you encounter issues with the tests:

1. **File path issues**: Make sure the tests can locate the main project files
2. **Port conflicts**: If API tests fail, check if the test ports are already in use
3. **Permissions**: Some tests may require appropriate permissions to bind to ports
4. **Timeouts**: For server tests, increase sleep times if necessary

## Test Documentation

For more details on specific test cases, refer to the docstrings in the individual test files.
