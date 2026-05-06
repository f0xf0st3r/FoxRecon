# Contributing to FoxRecon

Thank you for your interest in contributing to FoxRecon! This document provides guidelines for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Follow security best practices

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Commit with clear messages: `git commit -m "feat: add feature X"`
6. Push and open a PR

## Development Setup

```bash
# Clone your fork
git clone https://github.com/f0xf0st3r/FoxRecon.git
cd FoxRecon

# Create virtual environment
python -m venv .venv && source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/unit/ -v
```

## Pull Request Guidelines

### PR Title Format
Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

feat(scanners): add ffuf content discovery adapter
fix(api): resolve JWT token expiration edge case
docs(readme): update installation instructions
test(engine): add pipeline integration tests
refactor(db): optimize subdomain query performance
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### PR Description
- Link to related issues
- Describe what changed and why
- Include testing steps
- Add screenshots if UI-related

### Requirements
- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Code follows project style
- [ ] New features have tests
- [ ] Documentation updated
- [ ] No breaking changes without major version bump

## Architecture Guidelines

- Follow clean architecture principles
- Each scanner implements `BaseScanner` interface
- Use async/await for I/O operations
- Validate all inputs through `internal.utils.security`
- Use structured logging via `internal.utils.logging`
- Database models in `internal/database/models/`

## Security Guidelines

- Never commit secrets or credentials
- Use `SecureProcess` for all subprocess calls
- Validate all user inputs
- Follow responsible disclosure for vulnerabilities

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

## Requesting Features

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).

## License

By contributing, you agree your contributions will be licensed under the MIT License.
