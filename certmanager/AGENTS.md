# AGENTS.md

Parent guide: [../AGENTS.md](../AGENTS.md)

This module already has its own user-facing `README.md` — read that first for
feature/behavior details; this file adds AI-agent-specific notes on top of it
rather than duplicating it.

## Purpose

`certmanager` (packaged/deployed as `mosipcertmanager` — see naming note
below) checks MOSIP partner certificate expiry via the Partner Management
System (PMS) API and, for certificates that are expired or inside the
`pre-expiry-days` window, fetches the renewed certificate from the database,
uploads it back to PMS, and propagates it to the dependent system for that
partner type (eSignet, IDA, KeyManager for resident/digital-card partners, or
PMS itself for other partner kinds). Runs as a Kubernetes `CronJob`.

## Layout

```text
certmanager/
├── checkupdate.py         # entire script: checks expiry, renews, uploads, restarts esignet
├── README.md               # user-facing feature/config documentation (read this first)
├── Dockerfile               # python:3.9 base, installs kubectl + requirements.txt
├── requirements.txt         # psycopg2-binary, requests
├── bootstrap.properties     # local-only fallback config (placeholder values)
└── partner.properties       # local-only fallback list of partner IDs
```

Note the naming mismatch called out in the parent guide: this module's Helm
chart and deploy scripts live under `../helm/mosipcertmanager/` and
`../deploy/mosipcertmanager/`, not `certmanager`.

## How to run

```bash
cd certmanager
pip install -r requirements.txt
python checkupdate.py
```

The script also shells out to the `openssl` CLI (via `os.popen(...)`) to read
certificate expiry dates, and to `kubectl` (via `subprocess.run`) to restart
the eSignet deployment after a successful eSignet certificate upload — both
binaries are installed into the Docker image but must be available on `PATH`
if you run the script outside the container.

## Configuration

`checkupdate.py` reads each of these from an environment variable first, and
falls back to `read_bootstrap_properties()` (which parses `bootstrap.properties`
line-by-line) if the environment variable is unset:

- `db-host`, `db-port`, `db-su-user`, `postgres-password` — Postgres
  connection used to read certificate data directly from `mosip_pms` and
  `mosip_keymgr` databases when uploading a renewed certificate
- `mosip-api-internal-host` — internal MOSIP API host, used for auth,
  partner-manager, keymanager, and IDA calls
- `mosip-api-host` (env var name) / `mosip-api-external-host` (properties-file
  key) — external host, used only for the eSignet upload call
- `mosip_deployment_client_secret` — client secret used to authenticate
  against `/v1/authmanager/authenticate/clientidsecretkey`
- `pre-expiry-days` — renewal window in days

Two more variables are environment-only (no properties-file fallback):

- `PARTNER_IDS_ENV` — comma-separated partner IDs; if unset, the script reads
  `partner.properties`'s `PARTNER_ID=` line instead
- `ns_esignet` — Kubernetes namespace to restart the `esignet` deployment in
  after a successful eSignet certificate upload; if unset, the restart step
  is skipped (with a printed warning), not treated as an error

As with the other modules, `bootstrap.properties` in this repo holds masked
sandbox-style placeholder values (e.g. `postgres-password = HEdMa9Z****Tu**`)
pointing at `postgres.sandbox.mosip.net` — this is not a real usable
credential, and in a cluster deployment the real values come from a
Kubernetes Secret via `../deploy/mosipcertmanager/copy_secrets.sh`, not this
file.

## Repository-Specific Considerations

- Per this module's own `README.md`, it currently **cannot handle IDA-CRED
  certificates** — this is a documented, known gap, not a bug to silently
  "fix" without understanding the intended scope.
- The certificate-authentication request body sent to
  `/v1/authmanager/authenticate/clientidsecretkey` uses literal string values
  `"id": "string"` and `"version": "string"` — this matches the MOSIP auth
  API's expected envelope shape and is not a placeholder left by mistake.

## Agent rules

### Do

1. Read this module's `README.md` before making behavior changes — it
   documents the partner-type-to-dependent-system mapping in detail.
2. Preserve the "env var first, properties-file fallback" pattern for any new
   configuration value you add.
3. Remember the chart/deploy folder for this module is named
   `mosipcertmanager`, not `certmanager`, when cross-referencing Helm/deploy
   changes.

### Do not

1. Do not put a real `mosip_deployment_client_secret` or database password
   into `bootstrap.properties`.
2. Do not silently expand certificate handling to IDA-CRED certificates
   without confirming that's the intended scope of your task — it's an
   explicitly documented WIP gap.

Parent guide: [../AGENTS.md](../AGENTS.md)
