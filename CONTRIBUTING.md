# Contributing

Thank you for considering a contribution to Zero-Trust Agentic Guardian.

## Before You Start

- Search existing issues and pull requests before opening a new one.
- For substantial changes, open an issue first to align on scope.
- Keep pull requests focused and small where possible.

## Development Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
pip install -e .
```

3. Run tests:

```bash
pytest -m "not integration and not attack"
```

## Code Standards

- Target Python 3.14.2.
- Preserve existing architecture and security invariants.
- Add or update tests for behavior changes.
- Keep commits atomic and message them clearly.

## Pull Request Checklist

- Tests pass locally.
- New behavior is covered by tests.
- Documentation is updated if needed.
- Security-sensitive changes include rationale and risk notes.

## Reporting Security Issues

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the terms in [LICENSE](LICENSE).
