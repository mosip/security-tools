# AGENTS.md

## Repository Overview

`security-tools` is a collection of small, **independent** operational/security
utility scripts used to run and maintain a MOSIP deployment. There is no shared
application, shared library, or shared build — each module is its own
standalone Python script with its own Dockerfile, its own Helm chart, and its
own deploy scripts. Treat this repo as a toolbox, not a single service.

Modules (each is independently deployable as a Kubernetes CronJob):

| Module | Purpose | Guide |
| --- | --- | --- |
| `auditsweeper/` | Deletes old rows from the `audit.app_audit_log` table in the `mosip_audit` Postgres database, older than a configurable number of days. | [auditsweeper/AGENTS.md](auditsweeper/AGENTS.md) |
| `certmanager/` | Checks MOSIP partner certificate expiry (via PMS) and renews/re-uploads certificates to eSignet, IDA, KeyManager, or PMS as needed. | [certmanager/AGENTS.md](certmanager/AGENTS.md) |
| `databreachdetector/` | Scans Postgres tables for PII-shaped data (using the `deduce` library) and uploads findings reports to MinIO/S3. Marked **WIP** by its own README. | [databreachdetector/AGENTS.md](databreachdetector/AGENTS.md) |

Two more top-level directories support all three modules but are not modules
themselves:

- `deploy/` — per-module shell scripts (`install.sh`, `delete.sh`,
  `copy_cm.sh`, `copy_secrets.sh`) and `values.yaml` overrides used to install
  each Helm chart onto a cluster. Subfolders are `deploy/auditsweeper/`,
  `deploy/mosipcertmanager/`, `deploy/databreachdetector/` — note
  `mosipcertmanager` here corresponds to the `certmanager/` module (see
  Repository-Specific Considerations).
- `helm/` — the three Helm charts (`helm/auditsweeper/`,
  `helm/mosipcertmanager/`, `helm/databreachdetector/`), each deployed as a
  Kubernetes `CronJob`.

There is also a `pom.xml` and `src/Dummy.java` at the repo root. These are
**not** a real application — they are a placeholder Maven project that exists
only so the `sonar-check.yml` workflow (which runs `mvn verify sonar:sonar`)
has something to build. Do not treat `src/Dummy.java` as real product code.

## Technology Stack

- **Language**: Python 3.9 (all three modules; see each module's Dockerfile
  `FROM python:3.9`)
- **Key Python libraries** (per module, see each `requirements.txt`):
  `psycopg2-binary` (Postgres) everywhere; `requests` in `certmanager`;
  `python-stdnum`, `deduce`, `minio` in `databreachdetector`
- **Containers**: each module ships its own `Dockerfile`, built by CI
- **Orchestration**: Kubernetes `CronJob` via Helm charts under `helm/`
- **CI**: GitHub Actions (`.github/workflows/`) — Docker image builds, Helm
  chart lint/publish, and a SonarCloud scan of the placeholder Maven project
- **No test framework** is present anywhere in this repo (no `test_*.py`,
  `pytest`, or similar files exist as of this writing)

## Build & Test Commands

There is no root build. Each module is built and run independently.

Run a module directly with Python (from inside the module directory, after
installing its dependencies):

```bash
cd auditsweeper
pip install -r requirements.txt
python auditsweeper.py
```

```bash
cd certmanager
pip install -r requirements.txt
python checkupdate.py
```

```bash
cd databreachdetector
pip install -r requirements.txt
python databreachdetector.py
```

Build a module's Docker image (run from the module directory, matching what
`.github/workflows/push-trigger.yml` does per module):

```bash
cd auditsweeper
docker build -t auditsweeper:local .
```

There are no unit or integration tests to run in this repo. The only CI
quality gate is `sonar-check.yml`, which runs against the placeholder
`pom.xml` at the repo root:

```bash
mvn -B verify sonar:sonar -Dsonar.projectKey=mosip_security-tools -Dsonar.organization=mosip -Dsonar.host.url=https://sonarcloud.io -DskipSigning=true
```

Helm chart linting happens in CI only (`chart-lint-publish.yml`, triggered on
changes under `helm/**`) — there is no documented local lint command in this
repo; use `helm lint helm/<module>` if you need to check a chart locally.

## Configuration

Every module follows the same convention: **environment variables are
preferred; a checked-in `*.properties` file is the local-only fallback** used
when the required environment variables are not all set. This is implemented
directly in each script (e.g. `auditsweeper/auditsweeper.py`'s
`get_db_credentials()`, `certmanager/checkupdate.py`'s
`read_bootstrap_properties()`, `databreachdetector/databreachdetector.py`'s
`deduce_sensitive_data_in_databases()`).

In production, credentials are **not** committed — the `deploy/*/copy_secrets.sh`
scripts pull an existing Kubernetes Secret (e.g. `postgres-postgresql`) into
each module's namespace before Helm install; the Helm charts then mount that
secret into the CronJob's environment. See `deploy/auditsweeper/copy_secrets.sh`
and the corresponding `helm/*/templates/secrets.yaml` files.

The properties files committed to this repo
(`auditsweeper/local.properties`, `certmanager/bootstrap.properties`,
`databreachdetector/db.properties`) currently hold masked/sandbox-style
placeholder values (e.g. `HEdM***9ZXir7Tu2F`) pointing at MOSIP's own
sandbox/dev hosts, and `certmanager/partner.properties` lists sample partner
IDs — none of this is meant to be a real, usable credential. **Never replace
these placeholder values with real credentials or secrets in a commit or PR.**
See each module's `AGENTS.md` for the exact keys each file expects.

## Project Structure Notes

```text
security-tools/
├── auditsweeper/          # Postgres audit-log cleanup script + Dockerfile
├── certmanager/            # Partner certificate renewal script + Dockerfile + README
├── databreachdetector/     # PII scan script (WIP) + Dockerfile + README
├── deploy/
│   ├── auditsweeper/
│   ├── mosipcertmanager/   # deploy scripts for the certmanager module
│   └── databreachdetector/
├── helm/
│   ├── auditsweeper/
│   ├── mosipcertmanager/   # helm chart for the certmanager module
│   └── databreachdetector/
├── .github/workflows/      # docker build, helm lint/publish, sonar scan
├── pom.xml, src/Dummy.java # placeholder Maven project for the Sonar workflow only
```

Each module directory is self-contained: its Dockerfile `ADD`s or `COPY`s only
files from within that same directory, so there are no cross-module imports
or shared code to worry about when editing one module.

## Development Workflow

1. Fork the repo and branch from `develop` (the repo's default integration
   branch — confirmed via `git ls-tree`/`gh api` at branch-creation time).
2. Make changes scoped to a single module where possible; each module is
   independently versioned, built, and deployed.
3. If you change files under `helm/`, expect `chart-lint-publish.yml` to run
   (it triggers only on `pull_request`/`push` paths matching `helm/**`).
4. If you change `pom.xml` or `src/`, expect `sonar-check.yml` to run on push
   to `develop`; this workflow does not run on pull requests.
5. Any change under any module directory triggers `push-trigger.yml`'s
   Docker build matrix on `pull_request` and on push to `master`, `1.*`,
   `develop*`, `release*`, `MOSIP*`, or `update` branches.
6. There is no automated test suite — validate script changes by running the
   module locally against a test/sandbox database (or by manually reading
   through the change, since this repo has no CI test gate).

## Pull Request Guidelines

- Follow the standard MOSIP contribution flow: fork, feature branch off
  `develop`, PR back into `develop`.
- Keep PRs scoped to one module (`auditsweeper`, `certmanager`, or
  `databreachdetector`) unless the change is genuinely repo-wide (e.g. a
  workflow file).
- Sign off commits (`git commit -s`) per standard MOSIP DCO practice.
- Do not include real hostnames, credentials, tokens, or partner IDs from any
  live environment in a `*.properties` file, README, or commit message.
- If you touch `helm/*/Chart.yaml`, bump the chart `version` so the
  publish workflow produces a new package.

## Repository-Specific Considerations

- **Naming mismatch**: the source/module directory is `certmanager/`, but its
  Helm chart and deploy folder are both named `mosipcertmanager`
  (`helm/mosipcertmanager/`, `deploy/mosipcertmanager/`). Don't assume the
  names always match when navigating the repo.
- **`databreachdetector` is explicitly WIP** per its own README
  (`# Databreach detector (WIP)`). Treat behavior changes there as
  higher-risk/less-final than the other two modules.
- **`certmanager` has a documented limitation**: its README states it
  "can not handle IDA-CRED certificates" yet — don't assume full certificate
  coverage when reasoning about its behavior.
- **The root `pom.xml`/`src/Dummy.java` is a placeholder**, not real product
  code — do not try to "complete" it or add real Java sources there unless
  you are specifically changing how the Sonar workflow builds.
- **`sonar-check.yml` only runs on push to `develop`**, not on pull requests —
  don't expect a Sonar status check to appear on a PR from this repo's own
  workflows.
- Some scripts shell out to `openssl` and `kubectl` (e.g.
  `certmanager/checkupdate.py` calls `os.popen("... openssl x509 ...")`, and
  its Dockerfile installs `kubectl` for the `esignet` deployment restart) —
  these are expected to run inside the module's own container, not on an
  arbitrary local machine.

## Agent rules

### Do

1. Scope changes to a single module directory unless the task is explicitly
   repo-wide (e.g. a shared GitHub Actions workflow).
2. Verify which module a file belongs to by its actual path before editing —
   remember the `certmanager` / `mosipcertmanager` naming mismatch.
3. Keep the environment-variable-preferred, properties-file-fallback pattern
   intact when touching configuration-reading code in any module.
4. Update the relevant module's `AGENTS.md`/README if you change its
   configuration keys, CLI behavior, or dependencies.
5. Use placeholder/masked values (matching the existing style) if you need to
   add example configuration to a `*.properties` file.

### Do not

1. Do not commit real credentials, tokens, partner IDs, or hostnames into any
   `*.properties` file, Dockerfile, Helm `values.yaml`, or workflow file.
2. Do not assume this repo has a shared build, shared dependency set, or test
   suite — none exists; don't invent `pytest`/`mvn test` commands that aren't
   backed by real files.
3. Do not treat `pom.xml`/`src/Dummy.java` as the repo's real application.
4. Do not merge the three modules' code, dependencies, or Dockerfiles
   together — they are intentionally independent.
5. Do not remove or weaken the k8s-Secret-based credential flow
   (`deploy/*/copy_secrets.sh` + `helm/*/templates/secrets.yaml`) in favor of
   hardcoding credentials in a properties file.
