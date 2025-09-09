# Contributing to CodesHacks

We love your input! We want to make contributing to CodesHacks as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/yourusername/CodesHacks/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/yourusername/CodesHacks/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Use a Consistent Coding Style

* 4 spaces for indentation rather than tabs
* Use Python type hints where possible
* Follow PEP 8 guidelines
* Keep functions focused and modular
* Document complex algorithms

## Documentation

* Update the README.md with details of changes to the interface
* Update the HELP.md for new features or changed functionality
* Add docstrings to all new functions and classes
* Comment complex code sections

## Testing

* Write or update tests for new functionality
* Ensure all tests pass before submitting PR
* Include both unit tests and integration tests
* Test edge cases and error conditions

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to making participation in our project and our community a harassment-free experience for everyone.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

* Using welcoming and inclusive language
* Being respectful of differing viewpoints and experiences
* Gracefully accepting constructive criticism
* Focusing on what is best for the community
* Showing empathy towards other community members

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable behavior and are expected to take appropriate and fair corrective action in response to any instances of unacceptable behavior.

## Scope

This Code of Conduct applies both within project spaces and in public spaces when an individual is representing the project or its community.

## Pull Request Process

1. Update the README.md and HELP.md with details of changes to the interface
2. Update the requirements.txt if you add any dependencies
3. Include relevant test cases for new functionality
4. Ensure code follows the project's style guide
5. The PR will be merged once you have the sign-off of at least one other developer

## Development Setup

1. Clone your fork of the repo
```bash
git clone https://github.com/YOUR-USERNAME/CodesHacks
```

2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies
```bash
pip install -r requirements-dev.txt
```

4. Set up pre-commit hooks
```bash
pre-commit install
```

## License
By contributing, you agree that your contributions will be licensed under its MIT License.
