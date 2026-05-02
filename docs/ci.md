# CI pipelines

Seven GitHub Actions workflows run against this repository. This document describes what each one does, what it guarantees, and where tradeoffs were made.

## Workflows

### Lint & Test (`ci.yml`)

**Triggers:** push and PRs targeting `develop` or `main`

Runs two jobs in parallel:

- **Lint** — `ruff check`, `ruff format --check`, and `mypy` on Python 3.11.
- **Test** — `pytest` with coverage enforcement (`--cov-fail-under=80`) across Python 3.10, 3.11, and 3.12. Fail-fast is disabled so all three versions always report. The 3.11 run uploads a `.coverage` artifact used by `coverage.yml` for the combined badge.

**Guarantees:** the package is importable, typed, and tested on all supported Python versions before anything merges.

---

### Integration tests (`integration.yml`)

**Triggers:** push and PRs targeting `main` only (not `develop`)

Stands up the full [Greenbone Community Edition](https://greenbone.github.io/docs/latest/22.4/container/index.html#download) stack via Docker Compose, sets a known admin password, and runs `tests/integration/` against a live `gvmd` instance. Tests run under `--netaudit` (strace-level egress audit) and collect coverage for the GVM-dependent layer (`gvm_client.py`, `__main__.py`, `logging_config.py`), uploading a `.coverage` artifact for `coverage.yml`.

**Guarantees:** GMP authentication, session management, and the full tool call path work against a real scanner before anything reaches `main`. No unexpected outbound connections are made during the test run.

> [!NOTE]
> Integration tests only run on `main`-targeting branches. The full Greenbone stack is heavy (~30 container images). Fast feedback on feature branches comes from the unit tests in `ci.yml`.

**Known constraints:**

- **GHCR mirror** — Greenbone's registry (`registry.community.greenbone.net`) drops connections mid-transfer for large blobs from GitHub Actions runner IPs. All 19 Greenbone images are mirrored to `ghcr.io/cybersecauto-labs/greenbone/` and pulled from there instead. The mirror is kept fresh by the `mirror-greenbone-images.yml` workflow.
- **Auth secret** — the GHCR packages are private (pushed locally, not linked to this repository, so `GITHUB_TOKEN` cannot read them automatically). A `GHCR_READ_PAT` repo secret holds a PAT with `read:packages` scope. The long-term fix is to make the packages public or run the mirror workflow from `main` so packages get linked to the repo and `GITHUB_TOKEN` works automatically.

---

### Coverage badge (`coverage.yml`)

**Triggers:** `workflow_run` on either `Lint & Test` or `Integration tests` completing on `main` (push only, not PRs)

Runs two jobs:

- **Gate** — fires on whichever workflow finishes first. Checks whether the other has also completed for the same commit SHA via `gh run list`. If not, exits immediately without generating a badge.
- **Badge** — runs only when the gate confirms both artifacts exist. Downloads `coverage-unit` and `coverage-integration` by run ID, combines them with `coverage combine`, generates a unified XML report, and commits an updated `docs/coverage-badge.svg`.

**Guarantees:** the badge always reflects true combined coverage — unit tests cover the pure-logic layer; integration tests cover the GVM-dependent layer (`gvm_client.py`, `__main__.py`, `logging_config.py`). Each suite measures only what it can actually exercise, and the badge is never generated from partial data.

> [!NOTE]
> The badge is only updated after both workflows complete on `main`. On `develop` branches the badge is unchanged — fast-feedback coverage comes from the `--cov-fail-under=80` check in `ci.yml`.

---

### Docker (`docker.yml`)

**Triggers:** push and PRs targeting `develop` or `main`

Builds the `openvas-mcp` Docker image on every push and PR. Pushes to `ghcr.io/cybersecauto-labs/openvas-mcp:latest` only on direct push to `main` (not on PRs, to avoid polluting the image stream with unreviewed builds).

**Guarantees:** the image builds successfully and the `Dockerfile` is not broken before merge.

---

### Startup egress audit (`startup-egress.yml`)

**Triggers:** push and PRs targeting `develop` or `main`

Network egress is audited at two levels using [netaudit](https://pypi.org/project/netaudit/), which traces `connect()` syscalls via `strace` and fails on any connection to a non-loopback, non-Unix address:

- **Startup path** (`startup-egress.yml`) — runs `python -m openvas_mcp` directly under `netaudit run`. Catches any phone-home behaviour introduced by the server or its dependencies at import/startup time. Runs on every push to `develop` or `main` for fast feedback.
- **Live code paths** (`integration.yml`) — passes `--netaudit` to pytest, which re-execs the test process under strace and attributes any violation to the specific test that triggered it. Covers GMP calls, session management, and all tool handlers against a real `gvmd` instance.

**Guarantees:** the "local-first, no telemetry" claim is verified at the socket level on every push — both at startup and across the full tool call surface exercised by the integration tests.

---

### Release (`release.yml`)

**Triggers:** push of a version tag (`v*.*.*`)

Builds and pushes a versioned image to GHCR, signs it with [cosign](https://github.com/sigstore/cosign) keyless OIDC signing, generates a [CycloneDX](https://cyclonedx.org) SBOM with [syft](https://github.com/anchore/syft), scans it with [grype](https://github.com/anchore/grype) (fails on `high` severity findings), and creates a GitHub Release with the changelog, SBOM, and compose files attached.

**Guarantees:** every published image has a verifiable provenance chain (OIDC-signed by the Actions workflow identity, not a long-lived key), a bill of materials, and has passed a vulnerability scan at build time.

> [!NOTE]
> grype scans the SBOM at release time, not continuously. A CVE disclosed after a release will not re-trigger the scan. [Dependabot](https://docs.github.com/en/code-security/dependabot) handles dependency updates that feed into future releases.

---

### Mirror Greenbone images (`mirror-greenbone-images.yml`)

**Triggers:** weekly schedule (Mondays 04:00 UTC) and `workflow_dispatch`

Uses `skopeo copy --all` to copy all 19 [Greenbone Community Edition](https://greenbone.github.io/docs/latest/22.4/container/index.html#download) images from `registry.community.greenbone.net/community/` to `ghcr.io/cybersecauto-labs/greenbone/`, preserving multi-arch manifests.

**Guarantees:** the GHCR mirror stays reasonably fresh without manual intervention.

> [!NOTE]
> The weekly cadence means CI can run on images up to seven days old. Images are refreshed automatically after each new Greenbone stable release via the Monday schedule.
