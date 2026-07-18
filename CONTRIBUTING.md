# Contributing

Thank you for your interest in improving `grayhaven-timetracker`.

The application is organization-specific. Development and local UI testing
require separately supplied runtime branding, and deployment outside Grayhaven
requires adaptation to the target environment.

## Table of Contents

- [Development Setup](#development-setup)
- [Validation](#validation)
- [Pull Requests](#pull-requests)
- [Documentation Guidelines](#documentation-guidelines)

## Development Setup

Create and activate a Python 3.12 or newer virtual environment:

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

## Validation

Run the same application checks used by CI:

```bash
python3 -m pip_audit --progress-spinner off -r requirements.txt
python3 -m compileall -q grayhaven_timetracker scripts tests
mypy --strict grayhaven_timetracker scripts
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

Coverage includes line and branch measurement and fails below the 90% threshold
configured in `pyproject.toml`.

CI generates `coverage.xml` and uploads it to Codecov using GitHub Actions OIDC
authentication. No `CODECOV_TOKEN` repository secret is required. Project
coverage checks and pull request comments are configured in `codecov.yml`.

[Back to top](#contributing)

## Pull Requests

Create a focused feature branch for each change. Pull requests must:

- Reference or close a GitHub issue as appropriate.
- Contain signed commits.
- Have no open review conversations.
- Pass all CI checks.
- Include tests for changed behavior and security boundaries.
- Document operational or user-visible changes.

Sign each commit so GitHub can verify its authorship:

```bash
git commit -S -m "<message> (Refs #<issue-number>)"
```

Dependabot checks Python packages, the container base image, and GitHub Actions
weekly.

[Back to top](#contributing)

## Documentation Guidelines

Keep the project overview in [README.md](README.md), application structure in
[Application Architecture](docs/architecture.md), runtime settings in
[Configuration](docs/configuration.md), deployment procedures in
[Operations](docs/operations.md), and trust boundaries in
[Security](docs/security.md).

Use Python docstrings for module, class, and function responsibilities. Add
comments for non-obvious implementation decisions, security boundaries, and
assumptions without restating routine code.

[Back to top](#contributing)
