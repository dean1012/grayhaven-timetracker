# Contributing

Thank you for your interest in improving `grayhaven-timetracker`.

The application is organization-specific. Development and local UI testing
require separately supplied runtime branding, and deployment outside Grayhaven
requires adaptation to the target environment.

## Table of Contents

- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Validation](#validation)
- [Pull Requests](#pull-requests)
- [Container Releases](#container-releases)
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

Docker is required for container-image and Compose validation. ShellCheck,
actionlint, yamllint, and markdownlint-cli2 are required to run every CI check
locally.

[Back to top](#contributing)

## Development Workflow

1. Create a GitHub issue for the change.
2. Create a focused feature branch from the current `main` branch.
3. Make signed commits that reference the issue.
4. Run the relevant local validation.
5. Push the feature branch and open a pull request against `main`.
6. Resolve every review conversation and wait for all required checks to pass.
7. Squash merge the pull request and delete the feature branch.

Direct pushes to `main` are not part of the normal contribution workflow. The
protected branch accepts only squash merges, requires signed commits, and
requires the pull request branch to be current before merging.

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

## Container Releases

Container releases are created only from a clean, synchronized `main` branch
after CI succeeds for the exact commit. The public image is intentionally
unbranded; deployment automation supplies separately licensed branding at
runtime.

To prepare a release:

1. Fast-forward the local `main` branch from `origin/main` and confirm the
   worktree is clean.
2. Confirm CI and unit tests passed for the current commit.
3. Run `scripts/build-image`. The script builds the image locally and creates
   the next signed annotated `build/<version>` tag only after the build
   succeeds.
4. Verify the new tag with `git tag --verify build/<version>`.
5. Push only that tag with
   `git push origin refs/tags/build/<version>`.
6. Review the publishing workflow results and approve its
   `container-publish` environment gate.
7. Record the published GHCR digest and verify that the public image can be
   pulled without authentication.

The `publish.yml` workflow validates the signed tag and tagged revision before it
publishes the immutable version tag to
`ghcr.io/dean1012/grayhaven-timetracker`. It does not publish `latest`.
Deployment automation must select the reviewed image by digest.

Do not move, replace, reuse, or delete a published build tag. A correction
requires a new signed build tag and a new immutable image digest. GitHub Actions
does not create release tags or hold application, deployment, or branding
secrets.

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
