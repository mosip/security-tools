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
        "requesttime": "",
        "version": "string"
    }
    response = requests.post(auth_url, headers=headers, json=auth_data)
    if response.status_code == 200:
        return response.headers.get("authorization")
    print("Authentication failed.", response.text)
    return None

# Function to upload certificate
def upload_certificate_with_token(token, cert_data, partner_id, base_url):
    upload_url = f"https://{base_url}/v1/partnermanager/partners/certificate/upload"
    headers = {"Content-Type": "application/json", "Cookie": f"Authorization={token}"}
    upload_data = {
        "id": "string",
        "metadata": {},
        "request": {
            "certificateData": cert_data.replace("\\n", "\n"),
            "partnerDomain": "AUTH",
            "partnerId": partner_id
        },
        "requesttime": "",
        "version": "string"
    }
    response = requests.post(upload_url, headers=headers, json=upload_data)
    if "certificateId" not in response.text:
        print("Certificate renewal failed.", response.text)
    else:
        print("Certificate renewed successfully.")

# Fetching environment variables or values from bootstrap.properties
postgres_host = os.environ.get('db-host') or read_bootstrap_properties('db-host')
postgres_port = os.environ.get('db-port') or read_bootstrap_properties('db-port')
postgres_user = os.environ.get('db-su-user') or read_bootstrap_properties('db-su-user')
postgres_password = os.environ.get('postgres-password') or read_bootstrap_properties('postgres-password')
base_url = os.environ.get('mosip-api-internal-host') or read_bootstrap_properties('mosip-api-internal-host')
client_secret = os.environ.get('mosip_pms_client_secret') or read_bootstrap_properties('mosip_pms_client_secret')
pre_expiry_days = os.environ.get('pre-expiry-days') or read_bootstrap_properties('pre-expiry-days')
TOKEN = authenticate_and_get_token(base_url, client_secret)

if TOKEN:
    partner_ids = os.environ.get('PARTNER_IDS_ENV')
    if partner_ids:
        partner_ids = partner_ids.split(',')
        print ("Getting list of partners from env variable")
    else:
        with open('partner.properties', 'r') as file:
            for line in file:
                if line.startswith('PARTNER_ID'):
                    partner_ids = line.strip().split('=')[1].split(',')
                    print ("Getting list of partners from local variable")

    for PARTNER_ID in partner_ids:
        print(f"\nProcessing partner ID: {PARTNER_ID.strip()}")
        try:
            req = Request(f"https://{base_url}/v1/partnermanager/partners/{PARTNER_ID.strip()}/certificate",
                          headers={"Content-Type": "application/json", "Cookie": f"Authorization={TOKEN}"},
                          method="GET")
            response = urlopen(req)
            response_data = json.loads(response.read().decode('utf-8'))
            CERTIFICATE_DATA = response_data.get('response', {}).get('certificateData')
            expiration_date = os.popen(f"echo '{CERTIFICATE_DATA}' | openssl x509 -noout -enddate").read().split('=')[1].strip()
            if is_certificate_expired(expiration_date) or (datetime.strptime(expiration_date, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()) <= timedelta(days=int(pre_expiry_days)):
                write_to_expired_txt(PARTNER_ID.strip())
        except HTTPError as e:
            print(f"Error fetching certificate for {PARTNER_ID}: {e}")
            continue

    if os.path.exists("expired.txt"):
        with open("expired.txt", "r") as file:
            expired_partner_ids = [line.strip() for line in file if line.strip()]
    else:
        expired_partner_ids = []

    for partner_id in expired_partner_ids:
        cert_data = retrieve_certificate_data(partner_id, postgres_host, postgres_port, postgres_user, postgres_password)
        if cert_data:
            upload_certificate_with_token(TOKEN, cert_data, partner_id, base_url)
    print("Certificate check and renewal process completed.")
else:
    print("Failed to get auth-token")
