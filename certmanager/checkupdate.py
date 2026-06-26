import os
import sys
import json
import psycopg2
import requests
import subprocess
from datetime import datetime, timezone

REQUEST_TIMEOUT = 120

def validate_configuration():
    required_env_vars = [
        "PARTNERMANAGER_BASE_URL",
        "KEYMANAGER_BASE_URL",
        "IDA_BASE_URL",
        "db-host",
        "db-port",
        "db-su-user",
        "postgres-password",
        "mosip_pms_client_secret",
        "pre-expiry-days",
    ]

    present = [var for var in required_env_vars if os.environ.get(var)]

    if len(present) == len(required_env_vars):
        print("[CONFIG] Source: environment variables")
        return "env"

    if len(present) == 0:
        print("[CONFIG] Source: properties files (no environment variables detected)")
        return "file"

    missing = [var for var in required_env_vars if not os.environ.get(var)]
    print("[CONFIG ERROR] Partial environment configuration detected.")
    print(f"[CONFIG ERROR] Missing variables: {', '.join(missing)}")
    sys.exit(1)


def validate_bootstrap_properties():
    required_properties = [
        "PARTNERMANAGER_BASE_URL",
        "KEYMANAGER_BASE_URL",
        "IDA_BASE_URL",
        "db-host",
        "db-port",
        "db-su-user",
        "postgres-password",
        "mosip_pms_client_secret",
        "pre-expiry-days",
    ]

    missing = [key for key in required_properties if not read_bootstrap_properties(key)]

    if missing:
        print("[CONFIG ERROR] Missing entries in bootstrap.properties:")
        for item in missing:
            print(f"  - {item}")
        sys.exit(1)


def validate_partner_properties():
    # ESIGNET_INSTANCES and INJI_INSTANCES are optional — zero instances is valid.
    if read_partner_properties("PARTNER_ID") is None:
        print("[CONFIG ERROR] Missing PARTNER_ID in partner.properties.")
        sys.exit(1)


def read_bootstrap_properties(key):
    with open("bootstrap.properties", "r") as f:
        for line in f:
            if line.startswith(key) and "=" in line:
                return line.split("=", 1)[1].strip()
    return None


def read_partner_properties(key):
    try:
        with open("partner.properties", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None

    for i, line in enumerate(lines):
        if not line.startswith(key) or "=" not in line:
            continue

        value = line.split("=", 1)[1].strip()

        if not value.startswith("{"):
            return value

        # Multi-line JSON: accumulate lines until curly-brace depth reaches zero.
        depth = value.count("{") - value.count("}")
        j = i + 1
        while depth > 0 and j < len(lines):
            chunk = lines[j].strip()
            if chunk and not chunk.startswith("#"):
                value += "\n" + chunk
                depth += chunk.count("{") - chunk.count("}")
            j += 1

        return value

    return None


def load_partner_instance_mapping(config_source):
    esignet_mapping = {}
    inji_mapping = {}

    def get_raw(key):
        if config_source == "env":
            return os.environ.get(key, "{}")
        return read_partner_properties(key) or "{}"

    def parse_instances(label, raw):
        try:
            instances = json.loads(raw)
            if not isinstance(instances, dict):
                print(f"[CONFIG ERROR] {label}_INSTANCES must be a JSON object.")
                return {}
            return instances
        except Exception as e:
            print(f"[CONFIG ERROR] Failed to parse {label}_INSTANCES: {e}")
            return {}

    def build_mapping(label, instances, mapping):
        for name, cfg in instances.items():
            if not isinstance(cfg, dict):
                print(f"[CONFIG ERROR] Invalid config for {label} instance '{name}'.")
                continue

            url = cfg.get("url")
            namespace = cfg.get("namespace")
            deployment = cfg.get("deployment")
            partners = cfg.get("partners", [])

            missing = [k for k, v in [("url", url), ("namespace", namespace), ("deployment", deployment)] if not v]
            if missing:
                print(f"[CONFIG ERROR] {label} instance '{name}' is missing: {', '.join(missing)}.")
                continue

            if not isinstance(partners, list):
                print(f"[CONFIG ERROR] {label} instance '{name}': partners must be a list.")
                continue

            for pid in partners:
                pid = str(pid).strip()
                if pid:
                    mapping[pid] = {"url": url, "namespace": namespace, "deployment": deployment}

    esignet_instances = parse_instances("ESIGNET", get_raw("ESIGNET_INSTANCES"))
    inji_instances = parse_instances("INJI", get_raw("INJI_INSTANCES"))

    build_mapping("eSignet", esignet_instances, esignet_mapping)
    build_mapping("Inji", inji_instances, inji_mapping)

    return esignet_mapping, inji_mapping


def is_running_in_kubernetes():
    return os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")


def is_certificate_expired(expiration_date):
    expiry_dt = datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z")
    return datetime.utcnow() > expiry_dt


def write_to_expired_txt(partner_id):
    with open("expired.txt", "a") as f:
        f.write(partner_id + "\n")


def format_certificate(cert_data):
    if not cert_data:
        return None
    return cert_data.replace("\n", "\\n")


def retrieve_certificate_data(partner_id, db_host, db_port, db_user, db_password):
    pms_conn = pms_cursor = keymgr_conn = keymgr_cursor = None
    try:
        pms_conn = psycopg2.connect(
            host=db_host, port=db_port, database="mosip_pms",
            user=db_user, password=db_password
        )
        pms_cursor = pms_conn.cursor()
        pms_cursor.execute(
            "SELECT certificate_alias FROM pms.partner WHERE id = %s;",
            (partner_id,)
        )
        result = pms_cursor.fetchone()
        if not result:
            print(f"  [{partner_id}] No certificate alias found in PMS.")
            return None
        certificate_alias = result[0]

        keymgr_conn = psycopg2.connect(
            host=db_host, port=db_port, database="mosip_keymgr",
            user=db_user, password=db_password
        )
        keymgr_cursor = keymgr_conn.cursor()
        keymgr_cursor.execute(
            "SELECT cert_data FROM keymgr.partner_cert_store WHERE cert_id = %s;",
            (certificate_alias,)
        )
        result = keymgr_cursor.fetchone()
        if not result:
            print(f"  [{partner_id}] No certificate data found in Key Manager.")
            return None

        return format_certificate(result[0])

    except Exception as e:
        print(f"  [{partner_id}] Failed to retrieve certificate from DB: {e}")
        return None

    finally:
        for obj in (pms_cursor, pms_conn, keymgr_cursor, keymgr_conn):
            if obj:
                obj.close()

def get_utc_timestamp():
    return (
        datetime.utcnow()
        .replace(tzinfo=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

def extract_api_errors(response_json):
    errors = response_json.get("errors", [])
    messages = []
    for err in errors:
        if isinstance(err, dict):
            messages.append(
                err.get("message")
                or err.get("errorMessage")
                or err.get("defaultMessage")
                or str(err)
            )
        else:
            messages.append(str(err))
    return "; ".join(messages) if messages else None

def authenticate_and_get_token(base_url, client_secret):
    auth_url = f"https://{base_url}/v1/authmanager/authenticate/clientidsecretkey"
    auth_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "appId": "partner",
            "clientId": "mosip-pms-client",
            "secretKey": client_secret,
        },
        #"requesttime": get_utc_timestamp(),
        "version": "string",
    }

    try:
        response = requests.post(
            auth_url,
            headers={"Content-Type": "application/json"},
            json=auth_data,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        print(f"[ERROR] Authentication timed out after {REQUEST_TIMEOUT}s.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Authentication request failed: {e}")
        return None

    if response.status_code == 200:
        token = response.headers.get("authorization")
        if not token:
            print("[ERROR] Authentication succeeded but authorization token is missing in response headers.")
            return None
        return token

    print(f"[ERROR] Authentication failed (HTTP {response.status_code}): {response.text[:300].strip()}")
    return None

def upload_certificate_to_partnermanager(token, cert_data, partner_id, base_url, esignet_mapping, inji_mapping):
    upload_url = f"https://{base_url}/v1/partnermanager/partners/certificate/upload"
    special_partners = set(esignet_mapping) | set(inji_mapping)
    partner_domain = "MISP" if partner_id in special_partners else "AUTH"

    upload_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "certificateData": cert_data.replace("\\n", "\n"),
            "partnerDomain": partner_domain,
            "partnerId": partner_id,
        },
        #"requesttime": get_utc_timestamp(),
        "version": "string",
    }

    try:
        response = requests.post(
            upload_url,
            headers={"Content-Type": "application/json", "Cookie": f"Authorization={token}"},
            json=upload_data,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        print(f"  [{partner_id}] Upload to PartnerManager timed out after {REQUEST_TIMEOUT}s.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"  [{partner_id}] Upload to PartnerManager failed: {e}")
        return None

    try:
        response_json = response.json()
    except ValueError:
        print(f"  [{partner_id}] Upload to PartnerManager failed (HTTP {response.status_code}): non-JSON response.")
        return None

    if response.status_code not in (200, 201):
        error_text = extract_api_errors(response_json) or response.text[:300].strip()
        if "certificate dates not valid" in error_text.lower():
            error_text += " Please upload a fresh certificate with at least 1 year of validity."
        print(f"  [{partner_id}] Upload to PartnerManager failed (HTTP {response.status_code}): {error_text}")
        return None

    signed_certificate = response_json.get("response", {}).get("signedCertificateData")
    if not isinstance(signed_certificate, str) or not signed_certificate.strip():
        print(f"  [{partner_id}] Upload to PartnerManager succeeded but signedCertificateData is missing.")
        return None

    return signed_certificate

def upload_certificate_to_system(endpoint, token, app_id, cert_data, reference_id, partner_id, bearer=False):
    headers = {
        "Content-Type": "application/json",
        "Authorization" if bearer else "Cookie": f"Bearer {token}" if bearer else f"Authorization={token}",
    }
    payload = {
        "request": {
            "certificateData": cert_data,
            "applicationId": app_id,
            "referenceId": reference_id,
        },
        #"requestTime": get_utc_timestamp(),
    }

    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        print(f"  [{partner_id}] Upload to {app_id} timed out after {REQUEST_TIMEOUT}s.")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  [{partner_id}] Upload to {app_id} failed: {e}")
        return False

    try:
        response_json = response.json()
    except ValueError:
        response_json = None

    if response.status_code not in (200, 201):
        if response_json is not None:
            error_text = extract_api_errors(response_json) or response.text[:500].strip()
        else:
            error_text = response.text[:500].strip() or "(empty response body)"
        if "certificate dates not valid" in error_text.lower():
            error_text += " Please upload a fresh certificate with at least 1 year of validity."
        print(f"  [{partner_id}] Upload to {app_id} failed (HTTP {response.status_code}): {error_text}")
        return False

    return True

def parse_cert_expiry(pem):
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-enddate"],
        input=pem.encode(),
        capture_output=True,
    )
    output = proc.stdout.decode()
    if "=" not in output:
        return None, None
    end_date_str = output.split("=", 1)[1].strip()
    end_date = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
    days_left = (end_date - datetime.utcnow()).days
    return end_date_str, days_left

# Configuration 

config_source = validate_configuration()
if config_source == "file":
    validate_bootstrap_properties()
    validate_partner_properties()

if config_source == "env":
    postgres_host = os.environ.get("db-host")
    postgres_port = os.environ.get("db-port")
    postgres_user = os.environ.get("db-su-user")
    postgres_password = os.environ.get("postgres-password")

    partnermanager_base_url = os.environ.get("PARTNERMANAGER_BASE_URL")
    keymanager_base_url = os.environ.get("KEYMANAGER_BASE_URL")
    ida_base_url = os.environ.get("IDA_BASE_URL")
    pre_expiry_days = int(os.environ.get("pre-expiry-days"))
    client_secret = os.environ.get("mosip_pms_client_secret")
else:
    postgres_host = read_bootstrap_properties("db-host")
    postgres_port = read_bootstrap_properties("db-port")
    postgres_user = read_bootstrap_properties("db-su-user")
    postgres_password = read_bootstrap_properties("postgres-password")

    partnermanager_base_url = read_bootstrap_properties("PARTNERMANAGER_BASE_URL")
    keymanager_base_url = read_bootstrap_properties("KEYMANAGER_BASE_URL")
    ida_base_url = read_bootstrap_properties("IDA_BASE_URL")
    pre_expiry_days = int(read_bootstrap_properties("pre-expiry-days"))
    client_secret = read_bootstrap_properties("mosip_pms_client_secret")

# Authentication 

TOKEN = authenticate_and_get_token(partnermanager_base_url, client_secret)
if not TOKEN:
    print("[ERROR] Could not obtain auth token. Exiting.")
    sys.exit(1)

esignet_mapping, inji_mapping = load_partner_instance_mapping(config_source)

if config_source == "env":
    partner_ids_raw = os.environ.get("PARTNER_IDS_ENV", "")
else:
    partner_ids_raw = read_partner_properties("PARTNER_ID")

if not partner_ids_raw:
    print("[CONFIG ERROR] No partner IDs configured.")
    sys.exit(1)

partner_ids = [pid.strip() for pid in partner_ids_raw.split(",") if pid.strip()]

# Phase 1: Check certificate expiry

if os.path.exists("expired.txt"):
    os.remove("expired.txt")

print()
for partner_id in partner_ids:
    try:
        url = f"https://{partnermanager_base_url}/v1/partnermanager/partners/{partner_id}/certificate"
        headers = {"Content-Type": "application/json", "Cookie": f"Authorization={TOKEN}"}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code != 200:
            print(f"[{partner_id}] Could not fetch certificate (HTTP {response.status_code}): {response.text[:300].strip()}")
            continue

        try:
            response_data = response.json()
        except ValueError:
            print(f"[{partner_id}] Invalid JSON response from PartnerManager.")
            continue

        if not isinstance(response_data, dict):
            print(f"[{partner_id}] Unexpected response format from PartnerManager.")
            continue

        errors = response_data.get("errors")
        if errors:
            error_text = extract_api_errors({"errors": errors})
            print(f"[{partner_id}] PartnerManager returned errors: {error_text}")
            continue

        cert_info = response_data.get("response")
        cert_data = cert_info.get("certificateData") if cert_info else None

        if not cert_data:
            print(f"[{partner_id}] No certificate data in response — queuing for DB lookup.")
            write_to_expired_txt(partner_id)
            continue

        try:
            pem = cert_data.replace("\r\n", "\n").strip()
            expiration_date, days_left = parse_cert_expiry(pem)

            if expiration_date is None:
                print(f"[{partner_id}] Could not parse certificate — queuing for DB lookup.")
                write_to_expired_txt(partner_id)
                continue

        except Exception:
            print(f"[{partner_id}] Certificate parsing error — queuing for DB lookup.")
            write_to_expired_txt(partner_id)
            continue

        if is_certificate_expired(expiration_date) or days_left <= pre_expiry_days:
            print(f"[{partner_id}] Certificate expires in {days_left} day(s) — queued for renewal.")
            write_to_expired_txt(partner_id)
        else:
            print(f"[{partner_id}] Certificate is valid ({days_left} day(s) remaining).")

    except Exception as e:
        print(f"[{partner_id}] Unexpected error during expiry check: {e}")
        continue

# Phase 2: Renew expired certificates

if os.path.exists("expired.txt"):
    with open("expired.txt", "r") as f:
        seen = set()
        expired_partner_ids = []
        for line in f:
            pid = line.strip()
            if pid and pid not in seen:
                seen.add(pid)
                expired_partner_ids.append(pid)
else:
    expired_partner_ids = []

if expired_partner_ids:
    print()

for partner_id in expired_partner_ids:
    print(f"[{partner_id}] Renewing certificate ...")

    cert_data = retrieve_certificate_data(
        partner_id, postgres_host, postgres_port, postgres_user, postgres_password
    )
    if not cert_data:
        print(f"  [{partner_id}] Skipped — certificate not found in DB.")
        continue

    try:
        pem = cert_data.replace("\\n", "\n").replace("\r\n", "\n").strip()
        _, days_remaining = parse_cert_expiry(pem)

        if days_remaining is None:
            print(f"  [{partner_id}] Skipped — could not parse DB certificate.")
            continue

        if days_remaining < 365:
            print(
                f"  [{partner_id}] Skipped — DB certificate has only {days_remaining} day(s) of validity "
                f"(minimum required: 365 days). Upload a fresh certificate to Key Manager and re-run."
            )
            continue

    except Exception as e:
        print(f"  [{partner_id}] Skipped — DB certificate validation error: {e}")
        continue

    print(f"  [{partner_id}] Uploading to PartnerManager ...")
    signed_cert = upload_certificate_to_partnermanager(
        TOKEN, cert_data, partner_id, partnermanager_base_url, esignet_mapping, inji_mapping
    )
    if not signed_cert:
        continue

    post_upload_success = True

    if partner_id in esignet_mapping:
        instance = esignet_mapping[partner_id]
        print(f"  [{partner_id}] Uploading to eSignet ({instance['url']}) ...")
        post_upload_success = upload_certificate_to_system(
            f"https://{instance['url']}/v1/esignet/system-info/uploadCertificate",
            TOKEN, "OIDC_PARTNER", signed_cert, "", partner_id, bearer=True
        )
        if post_upload_success:
            if is_running_in_kubernetes():
                try:
                    subprocess.run(
                        ["kubectl", "rollout", "restart", "deployment",
                         instance["deployment"], "-n", instance["namespace"]],
                        check=True,
                    )
                    print(f"  [{partner_id}] Deployment '{instance['deployment']}' restarted.")
                except Exception as e:
                    print(f"  [{partner_id}] Deployment restart failed: {e}")
            else:
                print(f"  [{partner_id}] Skipping rollout restart (not running in Kubernetes) — manual restart of '{instance['deployment']}' may be needed.")

    elif partner_id in inji_mapping:
        instance = inji_mapping[partner_id]
        print(f"  [{partner_id}] Uploading to Inji Certify ({instance['url']}) ...")
        post_upload_success = upload_certificate_to_system(
            f"https://{instance['url']}/v1/certify/system-info/uploadCertificate",
            TOKEN, "CERTIFY_PARTNER", signed_cert, "", partner_id
        )

    elif partner_id == "mpartner-default-digitalcard":
        print(f"  [{partner_id}] Uploading to Key Manager (DIGITAL_CARD) ...")
        post_upload_success = upload_certificate_to_system(
            f"https://{keymanager_base_url}/v1/keymanager/uploadCertificate",
            TOKEN, "DIGITAL_CARD", signed_cert, partner_id, partner_id
        )

    elif partner_id == "mpartner-default-auth":
        print(f"  [{partner_id}] Uploading to IDA ...")
        post_upload_success = upload_certificate_to_system(
            f"https://{ida_base_url}/idauthentication/v1/internal/uploadCertificate",
            TOKEN, "IDA", signed_cert, partner_id, partner_id
        )

    elif partner_id == "mpartner-default-resident":
        print(f"  [{partner_id}] Uploading to Key Manager (RESIDENT) ...")
        post_upload_success = upload_certificate_to_system(
            f"https://{keymanager_base_url}/v1/keymanager/uploadCertificate",
            TOKEN, "RESIDENT", signed_cert, partner_id, partner_id
        )

    if post_upload_success:
        print(f"  [{partner_id}] Certificate renewed successfully.")

print("\nMOSIP CertManager completed.")
