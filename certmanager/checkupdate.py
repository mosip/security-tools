import os
import json
import psycopg2
import requests
import subprocess
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from datetime import datetime, timezone

REQUEST_TIMEOUT = 30

# Function to read value from bootstrap.properties
def read_bootstrap_properties(key):
    with open('bootstrap.properties', 'r') as file:
        for line in file:
            if line.startswith(key) and '=' in line:
                return line.split('=', 1)[1].strip()
    return None

# Helper function for local file fallback
def read_partner_properties(key):
    try:
        with open("partner.properties", "r") as file:
            for line in file:
                if line.startswith(key):
                    return line.split("=", 1)[1].strip()

    except FileNotFoundError:
        return None

    return None

# Function to build partner to instance mapping 
def load_partner_instance_mapping():
    esignet_mapping = {}
    inji_mapping = {}

    try:
        esignet_json = (
            os.environ.get("ESIGNET_INSTANCES")
            or read_partner_properties("ESIGNET_INSTANCES")
            or "{}"
        )
        esignet_instances = json.loads(esignet_json)

        if not isinstance(esignet_instances, dict):
            print(
                "[CONFIG ERROR] "
                "ESIGNET_INSTANCES "
                "must be a JSON object."
            )
            esignet_instances = {}

    except Exception as e:
        print(
            f"[CONFIG ERROR] "
            f"Failed to parse "
            f"ESIGNET_INSTANCES: {e}"
        )
        esignet_instances = {}

    try:
        inji_json = (
            os.environ.get("INJI_INSTANCES")
            or read_partner_properties("INJI_INSTANCES")
            or "{}"
        )
        inji_instances = json.loads(inji_json)

        if not isinstance(inji_instances, dict):
            print(
                "[CONFIG ERROR] "
                "INJI_INSTANCES "
                "must be a JSON object."
            )
            inji_instances = {}

    except Exception as e:
        print(
            f"[CONFIG ERROR] "
            f"Failed to parse "
            f"INJI_INSTANCES: {e}"
        )
        inji_instances = {}

    for instance_name, config in (esignet_instances.items()):
        if not isinstance(config, dict):
            print(
                f"[CONFIG ERROR] "
                f"Invalid configuration for "
                f"eSignet instance "
                f"'{instance_name}'"
            )
            continue

        url = config.get("url")
        namespace = config.get("namespace")
        partners = config.get("partners", [])
        deployment = config.get("deployment")

        if not deployment:
            print(
                f"[CONFIG ERROR] "
                f"Deployment missing for "
                f"eSignet instance "
                f"'{instance_name}'"
            )
            continue

        if not url:
            print(
                f"[CONFIG ERROR] "
                f"URL missing for "
                f"eSignet instance "
                f"'{instance_name}'"
            )
            continue

        if not namespace:
            print(
                f"[CONFIG ERROR] "
                f"Namespace missing for "
                f"eSignet instance "
                f"'{instance_name}'"
            )
            continue

        if not isinstance(partners, list):
            print(
                f"[CONFIG ERROR] "
                f"Partners must be a list "
                f"for eSignet instance "
                f"'{instance_name}'"
            )
            continue

        for partner_id in partners:
            esignet_mapping[partner_id] = {
                "url": url,
                "namespace": namespace,
                "deployment": deployment
            }

    for instance_name, config in (inji_instances.items()):
        if not isinstance(config, dict):
            print(
                f"[CONFIG ERROR] "
                f"Invalid configuration for "
                f"Inji instance "
                f"'{instance_name}'"
            )
            continue

        url = config.get("url")
        namespace = config.get("namespace")
        partners = config.get("partners", [])
        deployment = config.get("deployment")

        if not deployment:
            print(
                f"[CONFIG ERROR] "
                f"Deployment missing for "
                f"Inji instance "
                f"'{instance_name}'"
            )
            continue
            
        if not url:
            print(
                f"[CONFIG ERROR] "
                f"URL missing for "
                f"Inji instance "
                f"'{instance_name}'"
            )
            continue

        if not namespace:
            print(
                f"[CONFIG ERROR] "
                f"Namespace missing for "
                f"Inji instance "
                f"'{instance_name}'"
            )
            continue

        if not isinstance(partners, list):
            print(
                f"[CONFIG ERROR] "
                f"Partners must be a list "
                f"for Inji instance "
                f"'{instance_name}'"
            )
            continue

        for partner_id in partners:
            inji_mapping[partner_id] = {
                "url": url,
                "namespace": namespace,
                "deployment": deployment
            }

    return (esignet_mapping,inji_mapping)

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
    if not cert_data:
        return None
    return cert_data.replace("\n", "\\n")

# Function to retrieve certificate data from the database
def retrieve_certificate_data(partner_id, db_host, db_port, db_user, db_password):
    pms_conn = None
    keymgr_conn = None
    pms_cursor = None
    keymgr_cursor = None

    try:
        print(f"Connecting to PMS DB: {db_host}:{db_port}")
        pms_conn = psycopg2.connect(
            host = db_host,
            port = db_port,
            database = "mosip_pms",
            user = db_user,
            password = db_password
        )
        print("Connected to PMS DB")

        pms_cursor = pms_conn.cursor()
        pms_cursor.execute(
            """
            SELECT certificate_alias
            FROM pms.partner
            WHERE id = %s;
            """,
            (partner_id,)
        )

        result = pms_cursor.fetchone()
        if not result:
            print(f"[{partner_id}] No certificate alias found in PMS.")
            return None
        certificate_alias = result[0]

        # sql_query_cert_data = f"SELECT cert_data FROM keymgr.partner_cert_store WHERE cert_id = '{certificate_alias}';"
        print(f"Connecting to Key Manager DB: {db_host}:{db_port}")
        keymgr_conn = psycopg2.connect(
            host = db_host,
            port = db_port,
            database = "mosip_keymgr",
            user = db_user,
            password = db_password
        )
        print("Connected to Key Manager DB\n")

        keymgr_cursor = keymgr_conn.cursor()
        keymgr_cursor.execute(
            """
            SELECT cert_data
            FROM keymgr.partner_cert_store
            WHERE cert_id = %s;
            """,
            (certificate_alias,)
        )
        
        # cert_data = keymgr_cursor.fetchone()[0]
        result = keymgr_cursor.fetchone()
        if not result:
            print(f"[{partner_id}] No certificate data found in Key Manager.")
            return None
        cert_data = result[0]

        formatted_cert_data = format_certificate(cert_data)
        return formatted_cert_data

    except Exception as e:
        print(f"Error retrieving certificate data for Partner ID '{partner_id}': {str(e)}")
        return None
    
    finally:
        if pms_cursor:
            pms_cursor.close()

        if pms_conn:
            pms_conn.close()

        if keymgr_cursor:
            keymgr_cursor.close()

        if keymgr_conn:
            keymgr_conn.close()

# Function to get current UTC time in ISO 8601 format with milliseconds
def get_utc_timestamp():
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

# Function to authenticate and retrieve the token
def authenticate_and_get_token(base_url, client_secret):
    auth_url = (
        f"https://{base_url}"
        f"/v1/authmanager/authenticate/clientidsecretkey"
    )

    headers = {
        "Content-Type": "application/json"
    }

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

    try:
        response = requests.post(
            auth_url,
            headers = headers,
            json = auth_data,
            timeout = REQUEST_TIMEOUT
        )

    except requests.exceptions.Timeout:
        print(
            "Authentication failed: "
            f"Request timed out after "
            f"{REQUEST_TIMEOUT} seconds."
        )
        return None

    except requests.exceptions.RequestException as e:
        print(f"Authentication request failed: {str(e)}")
        return None

    if response.status_code == 200:
        token = response.headers.get("authorization")

        if not token:
            print(
                "Authentication succeeded "
                "but authorization header missing."
            )
            return None

        return token

    print(
        f"Authentication failed "
        f"(HTTP {response.status_code}): "
        f"{response.text[:300].strip()}"
    )

    return None

# Function to upload certificate
# Returns signedCertificateData if successful
def upload_certificate_with_token(token, cert_data, partner_id, base_url, esignet_mapping, inji_mapping):
    upload_url = (
        f"https://{base_url}"
        f"/v1/partnermanager/partners/certificate/upload"
    )

    headers = {
        "Content-Type": "application/json",
        "Cookie": f"Authorization={token}"
    }

    special_partners = set(list(esignet_mapping.keys()) + list(inji_mapping.keys()))
    partner_domain = ("MISP" if partner_id in special_partners else "AUTH")

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

    try:
        response = requests.post(
            upload_url,
            headers = headers,
            json = upload_data,
            timeout = REQUEST_TIMEOUT
        )

    except requests.exceptions.Timeout:
        print(
            f"[{partner_id}] Certificate renewal failed: "
            f"Request timed out after "
            f"{REQUEST_TIMEOUT} seconds."
        )
        return None

    except requests.exceptions.ConnectionError as e:
        print(
            f"[{partner_id}] Certificate renewal failed: "
            f"Connection error - {str(e)}"
        )
        return None

    except requests.exceptions.RequestException as e:
        print(
            f"[{partner_id}] Certificate renewal request failed: "
            f"{str(e)}"
        )
        return None

    try:
        response_json = response.json()

    except ValueError:
        print(
            f"[{partner_id}] Certificate renewal failed "
            f"(HTTP {response.status_code}): "
            f"Non-JSON response - "
            f"{response.text[:300].strip()}"
        )
        return None

    if response.status_code not in (200, 201):
        errors = response_json.get("errors", [])

        if errors:
            error_messages = []

            for err in errors:
                if isinstance(err, dict):
                    error_messages.append(
                        err.get("message")
                        or err.get("errorMessage")
                        or err.get("defaultMessage")
                        or str(err)
                    )
                else:
                    error_messages.append(str(err))

            error_text = "; ".join(error_messages)

            if "certificate dates not valid" in error_text.lower():
                error_text += (
                    ". Please upload a fresh "
                    "certificate with at least "
                    "1 year validity left."
                )

            print(
                f"[{partner_id}] "
                f"Certificate renewal failed "
                f"(HTTP {response.status_code}): "
                f"{error_text}"
            )

        else:
            print(
                f"[{partner_id}] "
                f"Certificate renewal failed "
                f"(HTTP {response.status_code}): "
                f"{response.text[:300].strip()}"
            )

        return None

    response_body = response_json.get("response", {})

    signed_certificate = response_body.get("signedCertificateData")

    if not isinstance(signed_certificate, str) or not signed_certificate.strip():
        print(
            f"[{partner_id}] "
            f"Certificate renewal failed: "
            f"Invalid or missing "
            f"signedCertificateData "
            f"in API response."
        )
        return None

    return signed_certificate


# Function to post-upload to dependent systems
def post_upload_to_system(endpoint, token, app_id, cert_data, reference_id, partner_id, bearer = False):
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

    try:
        response = requests.post(
            endpoint,
            headers = headers,
            json = payload,
            timeout = REQUEST_TIMEOUT
        )

    except requests.exceptions.Timeout:
        print(
            f"[{partner_id}] Certificate upload back to "
            f"[{app_id}] failed: Request timed out "
            f"after {REQUEST_TIMEOUT} seconds."
        )
        return False

    except requests.exceptions.ConnectionError as e:
        print(
            f"[{partner_id}] Certificate upload back to "
            f"[{app_id}] failed: Connection error - {str(e)}"
        )
        return False

    except requests.exceptions.RequestException as e:
        print(
            f"[{partner_id}] Certificate upload back to "
            f"[{app_id}] request failed: {str(e)}"
        )
        return False

    try:
        response_json = response.json()

    except ValueError:
        print(
            f"[{partner_id}] Certificate upload back to "
            f"[{app_id}] failed "
            f"(HTTP {response.status_code}): "
            f"Non-JSON response - "
            f"{response.text[:300].strip()}"
        )
        return False

    if response.status_code not in (200, 201):
        errors = response_json.get("errors", [])

        if errors:
            error_messages = []

            for err in errors:
                if isinstance(err, dict):
                    error_messages.append(
                        err.get("message")
                        or err.get("errorMessage")
                        or err.get("defaultMessage")
                        or str(err)
                    )
                else:
                    error_messages.append(str(err))
            
            error_text = "; ".join(error_messages)
            if "certificate dates not valid" in error_text.lower():
                error_text += (
                    ". Please upload a fresh "
                    "certificate with at least "
                    "1 year validity left."
            )

            print(
                f"[{partner_id}] Certificate upload back to "
                f"[{app_id}] failed "
                f"(HTTP {response.status_code}): "
                f"{error_text}"
            )

        else:
            print(
                f"[{partner_id}] Certificate upload back to "
                f"[{app_id}] failed "
                f"(HTTP {response.status_code}): "
                f"{response.text[:300].strip()}"
            )

        return False

    print(
        f"[{partner_id}] certificate uploaded back to "
        f"[{app_id}] successfully."
    )

    return True

# Load configuration
postgres_host = os.environ.get('db-host') or read_bootstrap_properties('db-host')
postgres_port = os.environ.get('db-port') or read_bootstrap_properties('db-port')
postgres_user = os.environ.get('db-su-user') or read_bootstrap_properties('db-su-user')
postgres_password = os.environ.get('postgres-password') or read_bootstrap_properties('postgres-password')

# base_url = os.environ.get('mosip-api-internal-host') or read_bootstrap_properties('mosip-api-internal-host')
# base_esignet_url = os.environ.get('mosip-api-host') or read_bootstrap_properties('mosip-api-external-host')

partnermanager_base_url = (os.environ.get('PARTNERMANAGER_BASE_URL') or read_bootstrap_properties('PARTNERMANAGER_BASE_URL'))
keymanager_base_url = (os.environ.get('KEYMANAGER_BASE_URL') or read_bootstrap_properties('KEYMANAGER_BASE_URL'))
ida_base_url = (os.environ.get('IDA_BASE_URL')or read_bootstrap_properties('IDA_BASE_URL'))

# esignet_base_url = (os.environ.get('ESIGNET_BASE_URL') or read_bootstrap_properties('ESIGNET_BASE_URL'))
# inji_certify_base_url = (os.environ.get('INJI_CERTIFY_BASE_URL')or read_bootstrap_properties('INJI_CERTIFY_BASE_URL'))

client_secret = os.environ.get('mosip_deployment_client_secret') or read_bootstrap_properties('mosip_deployment_client_secret')
pre_expiry_days = int(os.environ.get('pre-expiry-days') or read_bootstrap_properties('pre-expiry-days'))
# ns_esignet = os.environ.get('ns_esignet')
TOKEN = authenticate_and_get_token(partnermanager_base_url, client_secret)

if TOKEN:
    esignet_mapping, inji_mapping = load_partner_instance_mapping()

    partner_ids = os.environ.get('PARTNER_IDS_ENV')

    if partner_ids:
        partner_ids = [
            pid.strip()
            for pid in partner_ids.split(',')
            if pid.strip()
        ]

    else:
        partner_ids = []
        with open('partner.properties', 'r') as file:
            for line in file:
                if line.startswith('PARTNER_ID'):
                    partner_ids = [
                        pid.strip()
                        for pid in line.strip().split('=')[1].split(',')
                        if pid.strip()
                    ]
                    break
        
    if os.path.exists("expired.txt"):
        os.remove("expired.txt")

    for PARTNER_ID in partner_ids:
        # PARTNER_ID = PARTNER_ID.strip()
        print(f"\nProcessing partner ID: {PARTNER_ID}")
        try:
            req = Request(
                f"https://{partnermanager_base_url}/v1/partnermanager/partners/{PARTNER_ID}/certificate",
                headers={"Content-Type": "application/json", "Cookie": f"Authorization={TOKEN}"},
                method="GET"
            )
            response = urlopen(req, timeout = REQUEST_TIMEOUT)
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

        signed_cert = upload_certificate_with_token(
            TOKEN, 
            cert_data, 
            partner_id, 
            partnermanager_base_url,
            esignet_mapping,
            inji_mapping
        )
        if not signed_cert:
            continue

        # Post-upload to relevant systems
        success = True

        if partner_id in esignet_mapping:
            instance = esignet_mapping[partner_id]
            esignet_url = instance["url"]
            deployment = instance["deployment"]

            success = post_upload_to_system(f"https://{esignet_url}" "/v1/esignet/system-info/uploadCertificate", TOKEN, "OIDC_PARTNER", signed_cert, "", partner_id, bearer=True)

            if success:
                namespace = instance["namespace"]
                try:
                    subprocess.run(["kubectl", "rollout", "restart", "deployment", deployment, "-n", namespace], check = True)
                except Exception as e:
                    print(
                        f"[{partner_id}] "
                        f"Failed to restart deployment "
                        f"in namespace '{namespace}': {e}"
                    )
    
            #else:
            #    print(f"[{partner_id}] Upload to Esignet failed. Skipping restart.")

        elif partner_id in inji_mapping:
            instance = inji_mapping[partner_id]
            inji_url = instance["url"]
            deployment = instance["deployment"]

            success = post_upload_to_system(f"https://{inji_url}" "/v1/certify/system-info/uploadCertificate",
                TOKEN, "OIDC_PARTNER", signed_cert, "", partner_id, bearer=True)

            #if not success:
            #    print(f"[{partner_id}] Upload to Inji Certify failed.")

        elif partner_id == 'mpartner-default-digitalcard':
            success = post_upload_to_system(f"https://{keymanager_base_url}/v1/keymanager/uploadCertificate", TOKEN, "DIGITAL_CARD", signed_cert, partner_id, partner_id)
    
        elif partner_id == 'mpartner-default-auth':
            success = post_upload_to_system(f"https://{ida_base_url}/idauthentication/v1/internal/uploadCertificate", TOKEN, "IDA", signed_cert, partner_id, partner_id)

        elif partner_id == 'mpartner-default-resident':
            success = post_upload_to_system(f"https://{keymanager_base_url}/v1/keymanager/uploadCertificate", TOKEN, "RESIDENT", signed_cert, partner_id, partner_id)
        
        if success or (partner_id not in esignet_mapping
                       and partner_id not in inji_mapping
                       and partner_id not in ['mpartner-default-digitalcard',
                                             'mpartner-default-auth',
                                             'mpartner-default-resident']
        ):
            print(f"[{partner_id}] certificate renewed successfully and will be valid for 1 more year.")

    print("MOSIP Certificate Manager Run Completed.")

else:
    print("Failed to get auth-token")
