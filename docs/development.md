# CodesHacks Development Guide

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/RAJSHRIVASTAV397/CodesHacks.git
cd CodesHacks
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt -r requirements-dev.txt
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

## Development Tools

- **Black**: Code formatting
- **isort**: Import sorting
- **mypy**: Type checking
- **flake8**: Code linting
- **pytest**: Testing
- **pre-commit**: Git hooks

## Code Style

This project follows these style guidelines:
- PEP 8 via Black code formatter
- Type hints for all functions
- Docstrings for all modules, classes, and functions
- Maximum line length of 88 characters

## Testing

Run tests with:
```bash
pytest                 # Run all tests
pytest tests/test_scanner.py  # Run specific test file
pytest -v             # Verbose output
pytest --cov=./       # With coverage
```

## Docker Development

Build and run with Docker:
```bash
docker-compose up codeshacks    # Run the tool
docker-compose up tests         # Run tests
```

## Continuous Integration

GitHub Actions workflow runs:
1. Code style checks (Black, isort)
2. Type checking (mypy)
3. Linting (flake8)
4. Tests (pytest)
5. Security checks (bandit)

## Project Structure

```
codeshacks/
├── modules/           # Core modules
│   ├── scanners/     # Scanner implementations
│   │   ├── network/  # Network scanning
│   │   ├── web/      # Web scanning
│   │   ├── dns/      # DNS scanning
│   │   └── vuln/     # Vulnerability scanning
│   ├── core/         # Core functionality
│   └── utils/        # Utility functions
├── tests/            # Test files
├── docs/             # Documentation
└── nuclei/           # Nuclei templates
```

## Contributing

1. Create a feature branch:
```bash
git checkout -b feature/your-feature
```

2. Make your changes
3. Run tests and checks:
```bash
pre-commit run --all-files
pytest
```

4. Push changes and create a pull request

## Common Development Tasks

1. Adding a new scanner:
   - Add module in appropriate scanners directory
   - Add tests in tests directory
   - Update documentation
   - Register scanner in core modules

2. Adding new dependencies:
   - Add to requirements.txt or requirements-dev.txt
   - Update Dockerfile if needed
   - Document in installation guide

3. Adding new configuration:
   - Update config.json schema
   - Add validation in config manager
   - Document in configuration guide

## Debugging

1. Enable debug logging:
```bash
python codeshacks.py -d example.com --debug
```

2. Use VS Code debugger:
   - Launch configuration provided in .vscode/launch.json
   - Set breakpoints and inspect variables

## Performance Testing

1. Profile code:
```bash
python -m cProfile -o output.prof codeshacks.py -d example.com
```

2. Analyze results:
```bash
python -m pstats output.prof
```

## Security Considerations

- Never commit API keys or credentials
- Use environment variables for sensitive data
- Run security checks before merging:
```bash
bandit -r .
safety check
```
