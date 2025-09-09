"""Test utilities and fixtures for CodesHacks tests."""

import os
import pytest
from pathlib import Path

@pytest.fixture
def test_data_dir():
    """Return path to test data directory."""
    return Path(__file__).parent / 'fixtures'

@pytest.fixture
def test_config():
    """Return test configuration."""
    return {
        'threads': 5,
        'timeout': 5,
        'rate_limit': 10,
        'output_dir': 'test_results',
        'api_keys': {
            'shodan': 'test_key',
            'censys': 'test_key'
        }
    }

@pytest.fixture
def temp_output_dir(tmp_path):
    """Create and return a temporary output directory."""
    output_dir = tmp_path / 'test_output'
    output_dir.mkdir()
    return output_dir

@pytest.fixture
def test_domain():
    """Return a test domain for scanning."""
    return 'example.com'

@pytest.fixture
def mock_dns_data(test_data_dir):
    """Load mock DNS test data."""
    with open(test_data_dir / 'test_dns.txt', 'r') as f:
        return f.read().splitlines()

@pytest.fixture
def mock_ports_data(test_data_dir):
    """Load mock ports test data."""
    with open(test_data_dir / 'test_ports.txt', 'r') as f:
        return f.read().splitlines()

@pytest.fixture
def mock_web_data(test_data_dir):
    """Load mock web test data."""
    with open(test_data_dir / 'test_web.txt', 'r') as f:
        return f.read().splitlines()
