import os
import json
import psycopg2
import requests
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from datetime import datetime, timedelta, timezone
from configparser import ConfigParser

# Function to read value from bootstrap.properties
def read_bootstrap_properties(key):
    with open('bootstrap.properties', 'r') as file:
        for line in file:
            if line.startswith(key):
                return line.split('=')[1].strip()
    return None

# Function to check if certificate is expired
def is_certificate_expired(expiration_date):
    expiration_date = datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z")
    current_date = datetime.utcnow()
    return current_date > expiration_date

# Function to write expired certificates to a text file
def write_to_expired_txt(cert_name):
    with open('expired.txt', 'a') as file:
        file.write(cert_name + '\n')

# Function to format certificate data
def format_certificate(cert_data):
    return cert_data.replace("\n", "\\n")

# Function to retrieve certificate data from the database
def retrieve_certificate_data(partner_id, db_host, db_port, db_user, db_password):
    try:
        pms_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database="mosip_pms",
            user=db_user,
            password=db_password
        )
        pms_cursor = pms_conn.cursor()
        sql_query_cert_alias = f"SELECT certificate_alias FROM pms.partner WHERE id = '{partner_id}';"
        pms_cursor.execute(sql_query_cert_alias)
        certificate_alias = pms_cursor.fetchone()[0]

        sql_query_cert_data = f"SELECT cert_data FROM keymgr.partner_cert_store WHERE cert_id = '{certificate_alias}';"
        keymgr_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database="mosip_keymgr",
            user=db_user,
            password=db_password
        )
        keymgr_cursor = keymgr_conn.cursor()
        keymgr_cursor.execute(sql_query_cert_data)
        cert_data = keymgr_cursor.fetchone()[0]

        formatted_cert_data = format_certificate(cert_data)

        pms_cursor.close()
        pms_conn.close()
        keymgr_cursor.close()
        keymgr_conn.close()

        return formatted_cert_data
    except Exception as e:
        print(f"Error retrieving certificate data for Partner ID '{partner_id}': {str(e)}")
        return None

# Function to get current UTC time in ISO 8601 format with milliseconds
def get_utc_timestamp():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

# Function to authenticate and retrieve the token
def authenticate_and_get_token(base_url, client_secret):
    auth_url = f"https://{base_url}/v1/authmanager/authenticate/clientidsecretkey"
    headers = {"Content-Type": "application/json"}
    auth_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "appId": "ida",
            "clientId": "mosip-deployment-client",
            "secretKey": client_secret
        },
        "requesttime": get_utc_timestamp(),
        "version": "string"
    }
    response = requests.post(auth_url, headers=headers, json=auth_data)
    if response.status_code == 200:
        return response.headers.get("authorization")
    print("Authentication failed.")
    return None

# Function to upload certificate
# Returns signedCertificateData if successful
def upload_certificate_with_token(token, cert_data, partner_id, base_url):
    upload_url = f"https://{base_url}/v1/partnermanager/partners/certificate/upload"
    headers = {"Content-Type": "application/json", "Cookie": f"Authorization={token}"}
    partner_domain = "MISP" if partner_id == "mpartner-default-esignet" else "AUTH"
    upload_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "certificateData": cert_data.replace("\\n", "\n"),
            "partnerDomain": partner_domain,
            "partnerId": partner_id
        },
        "requesttime": get_utc_timestamp(),
        "version": "string"
    }
    response = requests.post(upload_url, headers=headers, json=upload_data)
    if "certificateId" not in response.text:
        print(f"[{partner_id}] Certificate renewal failed.")
        return None
    return json.loads(response.text)['response']['signedCertificateData']

# Function to post-upload to dependent systems
def post_upload_to_system(endpoint, token, app_id, cert_data, reference_id, bearer=False):
    if bearer:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    else:
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"Authorization={token}"
        }

    payload = {
        "request": {
            "certificateData": cert_data,
            "applicationId": app_id,
            "referenceId": reference_id
        },
        "requestTime": get_utc_timestamp()
    }

    response = requests.post(endpoint, headers=headers, json=payload)

    if response.status_code == 200 and 'Upload Success' in response.text:
        print(f"[{partner_id}] certificate uploaded back to [{app_id}] successfully.")
        return True
    else:
        print(f"[{partner_id}] certificate upload back to [{app_id}] failed.")
        return False

# Load configuration
postgres_host = os.environ.get('db-host') or read_bootstrap_properties('db-host')
postgres_port = os.environ.get('db-port') or read_bootstrap_properties('db-port')
postgres_user = os.environ.get('db-su-user') or read_bootstrap_properties('db-su-user')
postgres_password = os.environ.get('postgres-password') or read_bootstrap_properties('postgres-password')
base_url = os.environ.get('mosip-api-internal-host') or read_bootstrap_properties('mosip-api-internal-host')
base_esignet_url = os.environ.get('mosip-api-external-host') or read_bootstrap_properties('mosip-api-external-host')
client_secret = os.environ.get('mosip_deployment_client_secret') or read_bootstrap_properties('mosip_deployment_client_secret')
pre_expiry_days = int(os.environ.get('pre-expiry-days') or read_bootstrap_properties('pre-expiry-days'))
TOKEN = authenticate_and_get_token(base_url, client_secret)

if TOKEN:
    partner_ids = os.environ.get('PARTNER_IDS_ENV')
    if partner_ids:
        partner_ids = partner_ids.split(',')
        print("Getting list of partners from env variable")
    else:
        with open('partner.properties', 'r') as file:
            for line in file:
                if line.startswith('PARTNER_ID'):
                    partner_ids = line.strip().split('=')[1].split(',')
                    print("Getting list of partners from local variable")

    for PARTNER_ID in partner_ids:
        PARTNER_ID = PARTNER_ID.strip()
        print(f"\nProcessing partner ID: {PARTNER_ID}")
        try:
            req = Request(
                f"https://{base_url}/v1/partnermanager/partners/{PARTNER_ID}/certificate",
                headers={"Content-Type": "application/json", "Cookie": f"Authorization={TOKEN}"},
                method="GET"
            )
            response = urlopen(req)
            raw_data = response.read().decode('utf-8')
            try:
                response_data = json.loads(raw_data)
            except json.JSONDecodeError:
                print(f"[{PARTNER_ID}] Invalid JSON response.")
                continue

            if not response_data or not isinstance(response_data, dict):
                print(f"[{PARTNER_ID}] Invalid or empty response.")
                continue

            cert_info = response_data.get('response')
            CERTIFICATE_DATA = cert_info.get('certificateData') if cert_info else None

            if not CERTIFICATE_DATA:
                print(f"[{PARTNER_ID}] Certificate data not found.")
                continue

            expiration_date = os.popen(f"echo '{CERTIFICATE_DATA}' | openssl x509 -noout -enddate").read().split('=')[1].strip()
            expiry_dt = datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.utcnow()).days

            if is_certificate_expired(expiration_date) or days_left <= int(pre_expiry_days):
                print(f"[{PARTNER_ID}] Certificate is expired or will expire in {days_left} day(s). Renewing...")
                write_to_expired_txt(PARTNER_ID)
            else:
                print(f"[{PARTNER_ID}] Certificate is valid. {days_left} day(s) left.")

        except HTTPError as e:
            print(f"[{PARTNER_ID}] HTTP error while fetching certificate: {e}")
            continue
        except Exception as e:
            print(f"[{PARTNER_ID}] Unexpected error: {e}")
            continue

    if os.path.exists("expired.txt"):
        with open("expired.txt", "r") as file:
            expired_partner_ids = [line.strip() for line in file if line.strip()]
    else:
        expired_partner_ids = []

    for partner_id in expired_partner_ids:
        cert_data = retrieve_certificate_data(partner_id, postgres_host, postgres_port, postgres_user, postgres_password)
        if not cert_data:
            continue

        try:
            pem = cert_data.replace("\\n", "\n")
            end_date_str = os.popen(f"echo '{pem}' | openssl x509 -noout -enddate").read().split('=')[1].strip()
            end_date = datetime.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
            if (end_date - datetime.utcnow()).days < 365:
                print(f"DB cert for {partner_id} has less than 365 days left. Skipping.")
                continue
        except Exception as e:
            print(f"Error validating DB cert for {partner_id}: {e}")
            continue

        signed_cert = upload_certificate_with_token(TOKEN, cert_data, partner_id, base_url)
        if not signed_cert:
            continue

        # Post-upload to relevant systems
        success = True
        if partner_id == 'mpartner-default-esignet':
            success = post_upload_to_system(f"https://{base_esignet_url}/v1/esignet/system-info/uploadCertificate", TOKEN, "OIDC_PARTNER", signed_cert, "", bearer=True)
        elif partner_id == 'mpartner-default-digitalcard':
            success = post_upload_to_system(f"https://{base_url}/v1/keymanager/uploadCertificate", TOKEN, "DIGITAL_CARD", signed_cert, partner_id)
        elif partner_id == 'mpartner-default-auth':
            success = post_upload_to_system(f"https://{base_url}/idauthentication/v1/internal/uploadCertificate", TOKEN, "IDA", signed_cert, partner_id)
        elif partner_id == 'mpartner-default-resident':
            success = post_upload_to_system(f"https://{base_url}/v1/keymanager/uploadCertificate", TOKEN, "RESIDENT", signed_cert, partner_id)

        if success or partner_id not in [
            'mpartner-default-esignet', 'mpartner-default-digitalcard', 'mpartner-default-auth', 'mpartner-default-resident']:
            print(f"[{partner_id}] certificate renewed successfully and will be valid for 1 more year.")

    print("MOSIP Certificate Manager Run Completed.")
else:
    print("Failed to get auth-token")
