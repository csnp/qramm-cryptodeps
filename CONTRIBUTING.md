# Contributing to CryptoDeps

Thank you for your interest in contributing to CryptoDeps. This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git

### Setup

```bash
git clone https://github.com/csnp/qramm-cryptodeps.git
cd qramm-cryptodeps
make deps
make build
make test
```

## Development Workflow

### Running Tests

```bash
# Run all tests
make test

# Run tests without race detector (faster)
make test-short

# View coverage report
make coverage
```

### Code Style

```bash
# Format code
make fmt

# Run linter
make lint
```

## Contributing Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `make test`
5. Run linter: `make lint`
6. Commit with a descriptive message
7. Push and open a Pull Request

### Commit Messages

Use conventional commits:

```
feat: add support for Cargo.toml
fix: correct SHA-384 classification
docs: update installation instructions
test: add tests for npm parser
```

## Contributing Package Data

Help expand the crypto knowledge database by contributing analysis for packages not yet in the database.

### Finding Unknown Packages

```bash
# Scan a project and identify unknown packages
cryptodeps analyze /path/to/project --deep

# Look for "not in database" warnings
```

### Submitting Package Data

1. Analyze the package source code to identify crypto usage
2. Create a YAML entry following the schema in `data/packages/`
3. Submit a Pull Request with the new package data

### Package Entry Format

```yaml
name: "package-name"
ecosystem: "go"  # go, npm, pypi, maven
crypto:
  - algorithm: "RSA"
    type: "asymmetric"
    quantumRisk: "vulnerable"
    usage: "Key exchange"
    file: "crypto.go"
    evidence: "Uses crypto/rsa package"
```

## Reporting Issues

### Bug Reports

Include:
- CryptoDeps version (`cryptodeps version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant manifest file (sanitized)

### Feature Requests

Describe:
- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

## Code of Conduct

Be respectful and constructive. We're all here to improve quantum security.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## Questions

- Open an issue for questions
- Visit [QRAMM.org](https://qramm.org) for quantum readiness resources
- Contact [CSNP](https://csnp.org) for organizational inquiries
