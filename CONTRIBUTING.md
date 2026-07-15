# Contributing

This document is intended for Grayhaven Systems LLC employees and assumes that
the repository and local runtime branding have been configured appropriately.

If you are not a Grayhaven Systems LLC employee, support and contributions are
still welcome. The application remains organization-specific and may require
adaptation outside Grayhaven's environment.

## Table of Contents

- [Development Setup](#development-setup)
- [Workflow](#workflow)
- [Local Validation](#local-validation)
- [Pull Requests](#pull-requests)
- [Documentation Guidelines](#documentation-guidelines)

## Development Setup

Create and activate a Python 3.13 virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install runtime and development dependencies:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements-dev.txt
```

Docker is required for production-image and Compose validation. ShellCheck,
actionlint, yamllint, and markdownlint-cli2 are required to run every CI check
locally.

[Back to top](#contributing)

## Workflow

1. Create a GitHub issue.
2. Create a focused feature branch for the issue.
3. Sign all commits and reference the issue number.
4. Validate changes locally.
5. Create a pull request to the `main` branch for code review.

[Back to top](#contributing)

## Local Validation

Run the same application checks used by CI:

```bash
python3 -m pip_audit --progress-spinner off -r requirements.txt
python3 -m compileall -q grayhaven_timetracker scripts tests
mypy --strict grayhaven_timetracker scripts tests
ruff check grayhaven_timetracker scripts tests
ruff format --check grayhaven_timetracker scripts tests
python3 -m coverage run -m unittest discover -s tests -v
python3 -m coverage report
python3 -m coverage xml
```

Validate the repository and container definitions:

```bash
actionlint
shellcheck scripts/build-image
git ls-files '*.yml' '*.yaml' | xargs -r yamllint
docker compose config --quiet
docker build --build-arg APP_VERSION=local-validation \
  --tag grayhaven-timetracker:validation .
git ls-files '*.md' | xargs -r markdownlint-cli2
git diff --check
```

Coverage includes branch measurement and fails below the 90% threshold in
`pyproject.toml`. CI uploads `coverage.xml` to Codecov through GitHub Actions
OIDC; no Codecov token is required.

[Back to top](#contributing)

## Pull Requests

Pull requests must:

- Reference or close a GitHub issue as appropriate.
- Contain signed commits.
- Have no open review conversations.
- Pass all CI checks.
- Include tests for changed behavior and security boundaries.
- Document operational or user-visible changes.

[Back to top](#contributing)

## Documentation Guidelines

Keep user-visible behavior in [README.md](README.md), architecture decisions in
[Application Architecture](docs/architecture.md), and deployment procedures in
[Operations](docs/operations.md). Add comments for non-obvious security
boundaries and assumptions without restating routine code.

[Back to top](#contributing)
