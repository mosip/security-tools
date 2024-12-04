import os
import json
import psycopg2
import requests
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from datetime import datetime, timedelta
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
    # Parse expiration date string
    expiration_date = datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z")
    # Get current date
    current_date = datetime.utcnow()
    # Compare expiration date with current date
    return current_date > expiration_date

# Function to write expired certificates to a text file
def write_to_expired_txt(cert_name):
    with open('expired.txt', 'a') as file:
        file.write(cert_name + '\n')

# Function to format certificate data
def format_certificate(cert_data):
    # Replace line breaks with "\\n"
    formatted_cert_data = cert_data.replace("\n", "\\n")
    return formatted_cert_data

# Function to retrieve certificate data from the database
def retrieve_certificate_data(partner_id, db_host, db_port, db_user, db_password):
    try:
        # Connect to the PMS database
        pms_conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database="mosip_pms",
            user=db_user,
            password=db_password
        )
        pms_cursor = pms_conn.cursor()

        # Query to retrieve the certificate alias
        sql_query_cert_alias = f"SELECT certificate_alias FROM pms.partner WHERE id = '{partner_id}';"
        pms_cursor.execute(sql_query_cert_alias)
        certificate_alias = pms_cursor.fetchone()[0]

        # Query to retrieve cert_data using the certificate alias
        sql_query_cert_data = f"SELECT cert_data FROM keymgr.partner_cert_store WHERE cert_id = '{certificate_alias}';"

        # Connect to the Keymgr database
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

        # Format the certificate data
        formatted_cert_data = format_certificate(cert_data)

        # Close connections
        pms_cursor.close()
        pms_conn.close()
        keymgr_cursor.close()
        keymgr_conn.close()

        return formatted_cert_data

    except Exception as e:
        print(f"Error retrieving certificate data for Partner ID '{partner_id}', Check partner name in expired.txt: {str(e)}")
        return None

# Function to authenticate and retrieve the token
def authenticate_and_get_token(base_url, client_secret):
    auth_url = f"https://{base_url}/v1/authmanager/authenticate/clientidsecretkey"
    headers = {"Content-Type": "application/json"}

    auth_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "appId": "ida",
            "clientId": "mosip-pms-client",
            "secretKey": client_secret
        },
        "requesttime": "",  # Generate timestamp in desired format
        "version": "string"
    }

    response = requests.post(auth_url, headers=headers, json=auth_data)
    if response.status_code == 200:
        token = response.headers.get("authorization")
        return token
    else:
        print("Authentication failed.")
        print("Auth API Response:", response.text)
        return None

# Function to upload certificate with authentication token
def upload_certificate_with_token(token, cert_data, partner_id, base_url):
    upload_url = f"https://{base_url}/v1/partnermanager/partners/certificate/upload"
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"Authorization={token}"
    }

    # Format certificate data
    formatted_cert_data = cert_data.replace("\\n", "\n")

    upload_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "certificateData": formatted_cert_data,
            "partnerDomain": "AUTH",
            "partnerId": partner_id
        },
        "requesttime": "",  # Generate timestamp in desired format
        "version": "string"
    }

    response = requests.post(upload_url, headers=headers, json=upload_data)

    if "certificateId" not in response.text:
        print("Certificate renewal failed.")
        print("Upload API Response:", response.text)
    else:
        print("Certificate renewed successfully.")

# Fetching environment variables or values from bootstrap.properties
postgres_host = os.environ.get('db-host')
postgres_port = os.environ.get('db-port')
postgres_user = os.environ.get('db-su-user')
postgres_password = os.environ.get('postgres-password')
base_url = os.environ.get('mosip-api-internal-host')
client_secret = os.environ.get('mosip_pms_client_secret')
pre_expiry_days = os.environ.get('pre-expiry-days')

missing_env_vars = []

if not postgres_host:
    missing_env_vars.append('db-host')
if not postgres_port:
    missing_env_vars.append('db-port')
if not postgres_user:
    missing_env_vars.append('db-su-user')
if not postgres_password:
    missing_env_vars.append('postgres-password')
if not base_url:
    missing_env_vars.append('mosip-api-internal-host')
if not client_secret:
    missing_env_vars.append('mosip_pms_client_secret')
if not pre_expiry_days:
    missing_env_vars.append('pre-expiry-days')

# If any environment variables are not set, read from bootstrap.properties file
if missing_env_vars:
    print(f"Missing environment variables: {', '.join(missing_env_vars)}. Falling back to bootstrap.properties.")
    config = ConfigParser()
    config.read('bootstrap.properties')
    postgres_host = config.get('Database', 'db-host', fallback=postgres_host)
    postgres_port = config.get('Database', 'db-port', fallback=postgres_port)
    postgres_user = config.get('Database', 'db-su-user', fallback=postgres_user)
    postgres_password = config.get('Database', 'postgres-password', fallback=postgres_password)
    base_url = config.get('API', 'mosip-api-internal-host', fallback=base_url)
    client_secret = config.get('API', 'mosip_pms_client_secret', fallback=client_secret)
    pre_expiry_days = config.get('API', 'pre-expiry-days', fallback=pre_expiry_days)

# Authenticate and get the token
TOKEN = authenticate_and_get_token(base_url, client_secret)

# Check if token is obtained successfully
if TOKEN:
    # Read pre-expiry days from bootstrap.properties
    PRE_EXPIRY_DAYS = pre_expiry_days

    # PARTNER_IDS read from partner.properties
    with open('partner.properties', 'r') as file:
        for line in file:
            if line.startswith('PARTNER_ID'):
                partner_ids = line.strip().split('=')[1].split(',')
                for PARTNER_ID in partner_ids:
                    print(f"\nProcessing partner ID: {PARTNER_ID.strip()}")
                    # Request certificate information
                    try:
                        req = Request(f"https://{base_url}/v1/partnermanager/partners/{PARTNER_ID.strip()}/certificate",
                                      headers={
                                          "Content-Type": "application/json",
                                          "Cookie": f"Authorization={TOKEN}"
                                      },
                                      method="GET")
                        response = urlopen(req)
                        response_data = json.loads(response.read().decode('utf-8'))
                        CERTIFICATE_DATA = response_data.get('response', {}).get('certificateData')
                        print(CERTIFICATE_DATA)
                        # Run openssl command to print certificate details
                        openssl_command = f"echo '{CERTIFICATE_DATA}' | openssl x509 -noout -enddate"
                        expiration_date = os.popen(openssl_command).read().split('=')[1].strip()
                        print("Certificate expiration date:", expiration_date)
                        # Check if certificate is expired or pre-expiry
                        if is_certificate_expired(expiration_date) or \
                                (datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()) <= timedelta(days=int(PRE_EXPIRY_DAYS)):
                            write_to_expired_txt(PARTNER_ID.strip())
                    except HTTPError as e:
                        print(f"Error occurred while fetching certificate information for {PARTNER_ID}: {e}")
                        continue

                    if not CERTIFICATE_DATA:
                        print(f"No data available for {PARTNER_ID} in keymanager.")
                        continue

    # Check if expired.txt exists before trying to read from it
    if os.path.exists("expired.txt"):
        with open("expired.txt", "r") as file:
            expired_partner_ids = [line.strip() for line in file if line.strip()]
    else:
        expired_partner_ids = []

    # Check if any certificates were found to be expired
    if not expired_partner_ids:
        print("None of the certs have expired.")
        exit(0)

    for partner_id in expired_partner_ids:
        print(f"Certificate renewal started for Partner ID: {partner_id}")
        cert_data = retrieve_certificate_data(partner_id, postgres_host, postgres_port, postgres_user, postgres_password)
        if cert_data is not None:
            upload_certificate_with_token(TOKEN, cert_data, partner_id, base_url)

    print("Certificate check and renewal process completed.")
else:
    print("Failed while trying to get auth-token")
