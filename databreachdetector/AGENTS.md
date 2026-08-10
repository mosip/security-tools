# AGENTS.md

Parent guide: [../AGENTS.md](../AGENTS.md)

This module already has its own short `README.md`, which marks it **WIP**.
Read it first; this file adds AI-agent-specific notes on top of it.

## Purpose

`databreachdetector` scans rows of configured Postgres tables (currently just
the `resident` schema of the `mosip_resident` database — see
`databreachdetector.py`'s hardcoded `databases` list) for PII-shaped data
using the `deduce` de-identification library, plus custom regex checks for
emails, mobile numbers, names, ages, dates, URLs, and locations, and an ID
checksum check (Verhoeff algorithm via `python-stdnum`). Findings are written
to local text files and then uploaded to a MinIO/S3 bucket. Runs as a
Kubernetes `CronJob`.

## Layout

```text
databreachdetector/
├── databreachdetector.py   # entire script: scan, deduce, write findings, push to MinIO
├── README.md                 # WIP notice + one-line description
├── Dockerfile                 # python:3.9 base, installs requirements.txt
├── requirements.txt           # psycopg2-binary, python-stdnum, deduce, minio
└── db.properties               # local-only fallback config (placeholder/blank values)
```

## How to run

```bash
cd databreachdetector
pip install -r requirements.txt
python databreachdetector.py
```

Running the script writes several report files into the current directory
(`id.txt`, `mails.txt`, `mobile_numbers.txt`, `names.txt`, `ages.txt`,
`dates.txt`, `url.txt`, `locations.txt`) before attempting to upload them to
the configured MinIO bucket — expect these files to appear locally when
testing.

## Configuration

`deduce_sensitive_data_in_databases()` checks whether **all** of the
following environment variables are set; if even one is missing, it reads
`db.properties` instead (via `configparser`, not a per-key fallback like the
other two modules):

- `db-server`, `db-port`, `db-su-user`, `postgres-password` — Postgres
  connection (`PostgreSQL Connection` section in `db.properties`)
- `s3-host`, `s3-region`, `s3-user-key`, `s3-user-secret`, `s3-bucket-name` —
  MinIO/S3 connection (`MinIO Connection` section)

`db.properties` also has two scan-tuning sections read unconditionally from
the file (not overridable by environment variable in the current code):

- `[Ignored Tables]` `ignore_tables` — comma-separated table names to skip
- `[Ignored Columns]` `ignore_columns` — comma-separated column names to skip
- `[disabled_f]` `disabled` — groups to exclude from the `deduce` scan (e.g.
  `institutions`)

In this repo, `db.properties`'s `postgres-password` is masked as `#######`
and the MinIO secret fields are blank — there is no usable credential
committed here. In a cluster deployment, real values come from a Kubernetes
Secret via `../deploy/databreachdetector/copy_secrets.sh`, not this file.

## Repository-Specific Considerations

- This module is explicitly marked **WIP** by its own `README.md` — treat
  behavior changes as less final/more likely to need rework than the other
  two modules.
- The regex-based detectors (`find_names`, `find_ages`, `find_dates`,
  `find_urls`, `find_locations`) all use `re.match`, which only anchors at
  the **start** of the string — this looks like it may be an unintentional
  limitation (a match inside the middle of a longer string would be missed),
  but it is existing behavior; don't "fix" it silently as part of an
  unrelated change without flagging it, since it may be relied upon or may
  be a known issue already tracked elsewhere.
- Some MinIO-related error handling references `ResponseError` from
  `minio.error`; this class exists in the older `minio` versions pinned in
  `requirements.txt` (`minio==6.0.2`) — don't upgrade the `minio` dependency
  without also checking this import still resolves.

## Agent rules

### Do

1. Read `README.md`'s WIP notice before treating any behavior here as final.
2. Preserve the "all env vars set, else read `db.properties`" fallback logic
   if you touch configuration loading.
3. Keep `ignore_tables`/`ignore_columns`/`disabled` scan-tuning read from
   `db.properties` unless you're deliberately adding environment-variable
   overrides for them (none exist today).

### Do not

1. Do not put a real database password or MinIO secret key into
   `db.properties`.
2. Do not silently change the `re.match`-based regex detectors to `re.search`
   (or vice versa) as an incidental part of an unrelated change — call it out
   explicitly if you believe it's a bug worth fixing.
3. Do not upgrade `minio` in `requirements.txt` without verifying
   `minio.error.ResponseError` (or its replacement) still exists in the new
   version and updating the import accordingly.

Parent guide: [../AGENTS.md](../AGENTS.md)
