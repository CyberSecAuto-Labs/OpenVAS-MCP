# CI pipelines

Six GitHub Actions workflows run against this repository. This document describes what each one does, what it guarantees, and where tradeoffs were made.

## Workflows

### Lint & Test (`ci.yml`)

**Triggers:** push and PRs targeting `develop` or `main`

Runs three jobs in parallel:

- **Lint** — `ruff check`, `ruff format --check`, and `mypy` on Python 3.11.
- **Test** — `pytest` with coverage enforcement (`--cov-fail-under=80`) across Python 3.10, 3.11, and 3.12 in parallel. Fail-fast is disabled so all three versions always report.
- **Coverage badge** — downloads the 3.11 coverage XML artifact and commits an updated `docs/coverage-badge.svg` on push (skipped on PRs to avoid badge noise).

**Guarantees:** the package is importable, typed, and tested on all supported Python versions before anything merges.

---

### Integration tests (`integration.yml`)

**Triggers:** push and PRs targeting `main` only (not `develop`)

Stands up the full Greenbone Community Edition stack via Docker Compose, sets a known admin password, and runs `tests/integration/` against a live `gvmd` instance.

**Guarantees:** GMP authentication, session management, and the full tool call path work against a real scanner before anything reaches `main`.

**Tradeoffs and known constraints:**

- **GHCR mirror** — Greenbone's registry (`registry.community.greenbone.net`) drops connections mid-transfer for large blobs from GitHub Actions runner IPs. All 19 Greenbone images are mirrored to `ghcr.io/cybersecauto-labs/greenbone/` and pulled from there instead. The mirror is kept fresh by the `mirror-greenbone-images.yml` workflow.
- **QEMU emulation** — seven images (`gvmd`, `pg-gvm`, `pg-gvm-migrator`, `openvas-scanner`, `gsad`, `gvm-config`, `gvm-tools`) were initially mirrored from a Mac (arm64) and are therefore arm64-only in GHCR. The workflow registers QEMU via `docker/setup-qemu-action` so the amd64 CI runner can execute them transparently. This adds startup latency; the gvmd socket wait is set to 20 minutes to absorb it.
- **Auth secret** — the GHCR packages are private (they were pushed locally and are not linked to this repository, so `GITHUB_TOKEN` cannot read them automatically). A `GHCR_READ_PAT` repo secret holds a personal access token with `read:packages` scope. The long-term fix is to make the packages public so no PAT is needed.
- **Only on `main`-targeting branches** — the full Greenbone stack is heavy (~30 container images). Running it on every feature branch push would burn minutes for no signal. Fast feedback comes from the unit tests in `ci.yml`.

---

### Docker (`docker.yml`)

**Triggers:** push and PRs targeting `develop` or `main`

Builds the `openvas-mcp` Docker image on every push and PR. Pushes to `ghcr.io/cybersecauto-labs/openvas-mcp:latest` only on direct push to `main` (not on PRs, to avoid polluting the image stream with unreviewed builds).

**Guarantees:** the image builds successfully and the `Dockerfile` is not broken before merge.

---

### Telemetry audit (`telemetry-audit.yml`)

**Triggers:** push and PRs targeting `develop` or `main`

Builds the image and runs the server inside a `--network=none` Docker container (completely network-isolated). Any outbound TCP or DNS attempt fails immediately. The workflow scans the server output for references to known telemetry endpoints (`pypi.org`, `anthropic.com`, `sentry.io`, `segment.io`, etc.) and fails if any are found.

**Guarantees:** the server and its dependencies make no unexpected outbound connections on startup — the "local-first, no telemetry" claim is verified on every push, not just stated in the README.

**Tradeoffs:** the audit catches connections that produce output or fail loudly. A dependency that phones home silently (no log output, fire-and-forget) would pass. A full socket-level audit (e.g. `strace` or `tcpdump` inside the container) would be more thorough but is not implemented. This is tracked as a known limitation in [`docs/design.md`](design.md).

---

### Release (`release.yml`)

**Triggers:** push of a version tag (`v*.*.*`)

Builds and pushes a versioned image to GHCR, signs it with [cosign](https://github.com/sigstore/cosign) keyless OIDC signing, generates a CycloneDX SBOM with [syft](https://github.com/anchore/syft), scans it with [grype](https://github.com/anchore/grype) (fails on `high` severity findings), and creates a GitHub Release with the changelog, SBOM, and compose files attached.

**Guarantees:** every published image has a verifiable provenance chain (OIDC-signed by the Actions workflow identity, not a long-lived key), a bill of materials, and has passed a vulnerability scan at build time.

**Tradeoffs:** grype scans the SBOM at release time, not continuously. A CVE disclosed after a release will not re-trigger the scan. Dependabot handles dependency updates that feed into future releases.

---

### Mirror Greenbone images (`mirror-greenbone-images.yml`)

**Triggers:** weekly schedule (Mondays 04:00 UTC) and `workflow_dispatch`

Uses `skopeo copy --all` to copy all 19 Greenbone Community Edition images from `registry.community.greenbone.net/community/` to `ghcr.io/cybersecauto-labs/greenbone/`, preserving multi-arch manifests.

**Guarantees:** the GHCR mirror stays reasonably fresh without manual intervention.

**Tradeoffs:** the weekly cadence means CI can run on images up to seven days old. Images are refreshed automatically after each new Greenbone stable release via the Monday schedule.
