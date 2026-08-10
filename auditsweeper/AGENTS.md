# AGENTS.md

Parent guide: [../AGENTS.md](../AGENTS.md)

## Purpose

`auditsweeper` is a single Python script that deletes old rows from the
`audit.app_audit_log` table in the `mosip_audit` Postgres database. It is
meant to run as a scheduled Kubernetes `CronJob` (see
`../helm/auditsweeper/templates/cronjob.yaml`), not as a long-running
service.

## Layout

```text
auditsweeper/
├── auditsweeper.py      # entire script: reads config, connects to Postgres, deletes old rows
├── Dockerfile            # python:3.9 base, installs kubectl + requirements.txt, runs auditsweeper.py
├── requirements.txt      # psycopg2-binary==2.9.1
└── local.properties       # local-only fallback config (placeholder values, see below)
```

## How to run

Locally, with dependencies installed:

```bash
cd auditsweeper
pip install -r requirements.txt
python auditsweeper.py
```

As a container:

```bash
cd auditsweeper
docker build -t auditsweeper:local .
docker run --rm auditsweeper:local
```

Deployed to a cluster via Helm, using the scripts in
`../deploy/auditsweeper/` (`copy_cm.sh`, `copy_secrets.sh`, `install.sh`) —
see `../deploy/auditsweeper/README.md` for the install steps.

## Configuration

`get_db_credentials()` in `auditsweeper.py` requires all five of these to be
set as environment variables; if any are missing, it falls back to reading
`local.properties` in the current working directory:

- `db-host`
- `db-port`
- `db-su-user`
- `postgres-password`
- `log-age-days`

The database name (`mosip_audit`) is hardcoded in the script, not
configurable.

`local.properties` in this repo currently holds sandbox-style masked
placeholder values (e.g. `postgres-password=HEdM***9ZXir7Tu2F` pointing at
`postgres.dev1.mosip.net`). In a real cluster deployment, `postgres-password`
comes from a Kubernetes Secret copied in by
`../deploy/auditsweeper/copy_secrets.sh` (which pulls the `postgres-postgresql`
secret into the `auditsweeper` namespace), not from this file.

## Agent rules

### Do

1. Keep `get_db_credentials()`'s "env vars first, `local.properties` fallback"
   behavior intact if you touch it.
2. Use masked/placeholder-style values if you add example config to
   `local.properties`.

### Do not

1. Do not put a real database password into `local.properties`.
2. Do not change the hardcoded `mosip_audit` database name without also
   updating the Helm chart/values and this file.

Parent guide: [../AGENTS.md](../AGENTS.md)
