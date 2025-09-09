# Contributing Guidelines

Thank you for your interest in contributing to CodesHacks! This document provides guidelines and instructions for contributing to the project.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Process](#development-process)
4. [Pull Request Process](#pull-request-process)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Documentation](#documentation)

## Code of Conduct

### Our Pledge
We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv)

### Setup Development Environment
1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/codeshacks.git
   cd codeshacks
   ```

3. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```

4. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

### Project Structure
```
codeshacks/
├── codeshacks.py      # Main entry point
├── scanner.py         # Core scanning functionality
├── modules/           # Scanner modules
├── tests/            # Test files
├── docs/             # Documentation
└── requirements.txt  # Dependencies
```

## Development Process

### Branching Strategy
- `main` - Main development branch
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `release/*` - Release preparation
- `hotfix/*` - Production hotfixes

### Creating a New Feature
1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Implement your changes
3. Write tests
4. Update documentation
5. Commit your changes:
   ```bash
   git commit -m "feat: add new feature"
   ```

### Commit Message Format
Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `style:` - Code style/formatting
- `chore:` - Maintenance tasks

Example:
```
feat(scanner): add new SSL/TLS analysis module

- Add certificate chain validation
- Implement protocol version checks
- Add cipher suite analysis
```

## Pull Request Process

1. Update relevant documentation
2. Add/update tests
3. Ensure all tests pass
4. Update README.md if needed
5. Create a pull request with a clear description

### PR Title Format
```
type(scope): brief description

Example:
feat(scanner): add SSL/TLS analysis module
```

### PR Description Template
```markdown
## Description
Clear description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring
- [ ] Other (specify)

## Testing
Description of testing performed

## Documentation
List documentation changes made
```

## Coding Standards

### Python Style Guide
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for function parameters and return values
- Maximum line length: 100 characters
- Use descriptive variable names

### Example Code Style
```python
from typing import List, Dict, Optional

def analyze_target(
    domain: str,
    ports: List[int],
    timeout: Optional[int] = 10
) -> Dict[str, any]:
    """
    Analyze target domain with specified parameters.
    
    Args:
        domain: Target domain name
        ports: List of ports to scan
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary containing analysis results
    
    Raises:
        ScannerError: If analysis fails
    """
    results = {}
    try:
        # Implementation
        pass
    except Exception as e:
        raise ScannerError(f"Analysis failed: {str(e)}")
    
    return results
```

## Testing Guidelines

### Test Structure
- Use pytest for testing
- Place tests in the `tests/` directory
- Name test files with `test_` prefix
- Group related tests in classes

### Example Test
```python
import pytest
from scanner import Scanner

class TestScanner:
    @pytest.fixture
    def scanner(self):
        config = {
            'threads': 5,
            'timeout': 5
        }
        return Scanner(config)
    
    def test_port_scan(self, scanner):
        results = scanner.port_scan('example.com', [80, 443])
        assert isinstance(results, dict)
        assert len(results) > 0
```

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=.

# Generate coverage report
pytest --cov=. --cov-report=html
```

## Documentation

### Code Documentation
- Add docstrings to all modules, classes, and functions
- Follow [Google Python Style Guide](http://google.github.io/styleguide/pyguide.html) for docstrings
- Include usage examples in docstrings

### Project Documentation
- Update README.md for significant changes
- Add/update API documentation
- Include examples and screenshots where relevant

### Documentation Example
```python
def scan_subdomain(
    domain: str,
    wordlist: Optional[str] = None
) -> List[str]:
    """
    Perform subdomain enumeration for a domain.
    
    Args:
        domain: Target domain to scan
        wordlist: Optional path to custom wordlist
    
    Returns:
        List of discovered subdomains
    
    Example:
        >>> scanner = Scanner()
        >>> subdomains = scanner.scan_subdomain('example.com')
        >>> print(subdomains)
        ['www.example.com', 'api.example.com']
    """
    pass
```

## Questions and Support

- Open an issue for bugs or feature requests
- Join our community discussions
- Contact maintainers: support@codeshacks.com

## License

By contributing to CodesHacks, you agree that your contributions will be licensed under the MIT License.
