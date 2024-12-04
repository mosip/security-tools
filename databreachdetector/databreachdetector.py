import psycopg2
from configparser import ConfigParser
from stdnum import verhoeff
from deduce import Deduce
from minio import Minio
from minio.error import ResponseError
import re
import os

def is_valid_verhoeff(number):
    return verhoeff.is_valid(str(number))

def is_valid_email(email):
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    match = email_pattern.match(str(email))
    return bool(match)

def is_valid_mobile_number(phone_number):
    pattern = re.compile(r'^[912345678]\d{9}$')
    match = re.match(pattern, str(phone_number))
    return bool(match)

def find_names(text):
    # Regular expression pattern to match names
    pattern = re.compile(r'\b[A-Z][a-z]*\s[A-Z][a-z]*\b')
    match =re.match(pattern,str(text))
    return bool(match)

def find_ages(text):
    # Regular expression pattern to match ages
    pattern = re.compile(r'\b\d{1,2}\s*(?:years?|yrs?|yo|y\.o\.|months?|mos?)\b')
    match =re.match(pattern,str(text))
    return bool(match)

def find_dates(text):
    # Regular expression pattern to match dates in formats like DD/MM/YYYY or MM/DD/YYYY
    pattern = r'\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b'
    match =re.match(pattern,str(text))
    return bool(match)

def find_urls(text):
    # Regular expression pattern to match URLs
    pattern = r'\b(?:https?://|www\.)\S+\b'
    match =re.match(pattern,str(text))
    return bool(match)

def find_locations(text):
    # Regular expression pattern to match common location patterns
    pattern = r'\b(?:city|town|village|state|province|country|continent|island)\s(?:of\s)?(?:\b[A-Z][a-z]*\b\s?)+'
    match =re.match(pattern,str(text))
    return bool(match)

def deduce_sensitive_data(connection, database_name, schema_name, output_file, ignore_columns, ignore_tables):
    deduce_instance = Deduce()

    with connection.cursor() as cursor:
        cursor.execute(f"SET search_path TO {schema_name}")
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (schema_name,))
        tables = [table[0] for table in cursor.fetchall()]

        with open(output_file, 'a') as deduced_file:
            for table_name in tables:
                if ignore_tables and table_name in ignore_tables:
                    # print(f"Ignoring Table: {table_name} in Database: {database_name}")
                    continue

                print(f"Currently checking Table: {table_name} in Database: {database_name}")
                deduced_file.write(f"Currently checking Table: {table_name} in Database: {database_name}\n")

                cursor.execute(f'SELECT * FROM {table_name}')
                rows = cursor.fetchall()

                id_count = 0
                mail_count = 0
                mobile_count = 0
                name = 0
                age = 0
                date = 0
                url = 0
                locations = 0
                for row in rows:
                    for i, column_value in enumerate(row):
                        column_name = cursor.description[i][0]

                        if ignore_columns and column_name in ignore_columns:
                            continue
                        config = ConfigParser()
                        deduced_result = deduce_instance.deidentify(
                            #getting the disabled groups from db.properties file.
                            str(column_value),
                            disabled= config.get('disabled_f', 'disabled', fallback='')
                        )

                        if deduced_result.annotations and is_valid_verhoeff(column_value):
                            id_count += 1
                            deduced_file.write(f"Column: {column_name}, Data: {column_value}\n")
                            deduced_file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                        with open('mobile_numbers.txt', 'a') as file:
                            if deduced_result.annotations and is_valid_mobile_number(column_value):
                                mobile_count += 1
                                file.write(f"Column: {column_name}, Data: {column_value}\n")
                                file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                        with open('mails.txt', 'a') as file:
                            if deduced_result.annotations and is_valid_email(column_value):
                                mail_count += 1
                                file.write(f"Column: {column_name}, Data: {column_value}\n")
                                file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                        
                            if deduced_result.annotations and find_names(column_value):
                                with open('names.txt', 'a') as file:
                                    name += 1
                                    file.write(f"Column: {column_name}, Data: {column_value}\n")
                                    file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")
                                    
                            if deduced_result.annotations and find_ages(column_value):
                                with open('ages.txt', 'a') as file:
                                    age += 1
                                    file.write(f"Column: {column_name}, Data: {column_value}\n")
                                    file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                            if deduced_result.annotations and find_dates(column_value):
                                with open('dates.txt', 'a') as file:
                                    date += 1
                                    file.write(f"Column: {column_name}, Data: {column_value}\n")
                                    file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                            if deduced_result.annotations and find_urls(column_value):
                                with open('url.txt', 'a') as file:
                                    url += 1
                                    file.write(f"Column: {column_name}, Data: {column_value}\n")
                                    file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                            if deduced_result.annotations and find_locations(column_value):
                                with open('locations.txt', 'a') as file:
                                    locations += 1
                                    file.write(f"Column: {column_name}, Data: {column_value}\n")
                                    file.write(f"Deduced Findings: {deduced_result.annotations}\n\n")

                print(f"{mail_count} mail id's, {mobile_count} mobile numbers, {id_count} id's, {name} names, {age} ages, {date} dates, {url} urls, {locations} locations are found in {table_name} table in {database_name} database")

def push_reports_to_s3(s3_host, s3_region, s3_user_key, s3_user_secret, s3_bucket_name):
    mc = Minio(s3_host,
               access_key=s3_user_key,
               secret_key=s3_user_secret,
               region=s3_region,
               secure=False)  # Set secure=True if using HTTPS

    try:
        if not mc.bucket_exists(s3_bucket_name):
            mc.make_bucket(s3_bucket_name, location=s3_region)

        # Ensure files exist before attempting to upload
        for filename in ['id.txt', 'mails.txt', 'mobile_numbers.txt','names.txt','ages.txt','dates.txt','urls.txt','locations.txt']:
            open(filename, 'a').close()

        mc.fput_object(s3_bucket_name, 'reports/id.txt', 'id.txt')
        mc.fput_object(s3_bucket_name, 'reports/mails.txt', 'mails.txt')
        mc.fput_object(s3_bucket_name, 'reports/mobile_numbers.txt', 'mobile_numbers.txt')
        mc.fput_object(s3_bucket_name, 'reports/names.txt', 'names.txt')
        mc.fput_object(s3_bucket_name, 'reports/ages.txt', 'ages.txt')
        mc.fput_object(s3_bucket_name, 'reports/dates.txt', 'dates.txt')
        mc.fput_object(s3_bucket_name, 'reports/url.txt', 'url.txt')
        mc.fput_object(s3_bucket_name, 'reports/locations.txt', 'locations.txt')
        print("\nReports pushed to MinIO")

    except ResponseError as err:
        print(f"MinIO Error: {err}")

def deduce_sensitive_data_in_databases():
    # Initialize config variable
    config = ConfigParser()

    # If environment variables are not set, read from db.properties file
    if not all([os.environ.get('db-server'), os.environ.get('db-port'), os.environ.get('db-su-user'),
                os.environ.get('postgres-password'), os.environ.get('s3-host'), os.environ.get('s3-region'),
                os.environ.get('s3-user-key'), os.environ.get('s3-user-secret'), os.environ.get('s3-bucket-name')]):
        config.read('db.properties')

    # Read PostgreSQL and MinIO details from environment variables or db.properties
    db_server = os.environ.get('db-server') or config.get('PostgreSQL Connection', 'db-server', fallback='')
    db_port = os.environ.get('db-port') or config.get('PostgreSQL Connection', 'db-port', fallback='')
    db_user = os.environ.get('db-su-user') or config.get('PostgreSQL Connection', 'db-su-user', fallback='')
    db_password = os.environ.get('postgres-password') or config.get('PostgreSQL Connection', 'postgres-password', fallback='')

    minio_host = os.environ.get('s3-host') or config.get('MinIO Connection', 's3-host', fallback='')
    minio_region = os.environ.get('s3-region') or config.get('MinIO Connection', 's3-region', fallback='')
    minio_user_key = os.environ.get('s3-user-key') or config.get('MinIO Connection', 's3-user-key', fallback='')
    minio_user_secret = os.environ.get('s3-user-secret') or config.get('MinIO Connection', 's3-user-secret', fallback='')
    minio_bucket_name = os.environ.get('s3-bucket-name') or config.get('MinIO Connection', 's3-bucket-name', fallback='')

    # Read ignored tables and columns from db.properties
    ignore_tables_str = config.get('Ignored Tables', 'ignore_tables', fallback='')
    ignore_columns_str = config.get('Ignored Columns', 'ignore_columns', fallback='')

    ignore_tables = [table.strip() for table in ignore_tables_str.split(',')] if ignore_tables_str else []
    ignore_columns = [column.strip() for column in ignore_columns_str.split(',')] if ignore_columns_str else []

    # Define the databases list
    databases = [
        {"name": "mosip_resident", "schema": "resident"},
        # Add other databases as needed
    ]

    connection = psycopg2.connect(
        host=db_server,
        port=db_port,
        user=db_user,
        password=db_password,
        database=databases[0]['name']
    )

    try:
        output_file_path = 'id.txt'

        for db_info in databases:
            print(f"\nAnalyzing data in Database: {db_info['name']}\n")
            deduce_sensitive_data(connection, db_info['name'], db_info['schema'], output_file_path, ignore_columns,
                                   ignore_tables)

        print(f"\nDeduced findings saved to respective text files")

        # Add the following lines to push reports to MinIO
        s3_host = minio_host
        s3_region = minio_region
        s3_user_key = minio_user_key
        s3_user_secret = minio_user_secret
        s3_bucket_name = minio_bucket_name

        push_reports_to_s3(s3_host, s3_region, s3_user_key, s3_user_secret, s3_bucket_name)

    finally:
        connection.close()

# Call the main function
deduce_sensitive_data_in_databases()
