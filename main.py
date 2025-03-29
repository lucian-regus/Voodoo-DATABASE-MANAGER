import os
from time import sleep
import requests
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

load_dotenv()

target_database_name = os.getenv('TARGET_DATABASE_NAME')
target_api = os.getenv('TARGET_API')

def create_connection(database_name):
    user = os.getenv('DATABASE_USER')
    password = os.getenv('DATABASE_PASSWORD')

    connection = psycopg2.connect(
        dbname=database_name,
        user=user,
        password=password,
        host="localhost",
        port="5432"
    )

    return connection

def create_database():
    connection = create_connection('postgres')

    connection.autocommit = True
    cursor = connection.cursor()

    quoted_dbname = sql.Identifier(target_database_name)

    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (target_database_name,))
    if not cursor.fetchone():
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(quoted_dbname))

    cursor.close()
    connection.close()

def create_tables():
    with open('schema.sql', 'r') as file:
        schema_sql = file.read()

    connection = create_connection(target_database_name)

    cursor = connection.cursor()

    cursor.execute(schema_sql)

    cursor.close()
    connection.commit()
    connection.close()

def update_database():
    while True:
        connection = create_connection(target_database_name)
        cursor = connection.cursor()

        cursor.execute("SELECT last_update FROM database_update_log ORDER BY last_update DESC LIMIT 1;")
        last_update = cursor.fetchone()

        target = f'{target_api}/api/database/updates'
        if last_update:
            target = f'{target}?delta={last_update[0].strftime('%Y-%m-%dT%H:%M:%S.%f')}'

        response = requests.get(target)

        signatures = response.json().get('malwareSignatures')
        yara_rules = response.json().get('yaraRules')
        blacklisted_ips = response.json().get('blacklistedIpAddresses')

        if signatures:
            signatures = [(entry['signature'],) for entry in signatures]

            cursor.executemany("""
                               INSERT INTO malware_signatures (signature)
                               VALUES (%s);
                               """, signatures)
            connection.commit()

        if yara_rules:
            yara_rules = [(entry['rule'],) for entry in yara_rules]

            cursor.executemany("""
                               INSERT INTO yara_rules (rule)
                               VALUES (%s);
                               """, yara_rules)
            connection.commit()

        if blacklisted_ips:
                blacklisted_ips = [(entry['ipAddress'],) for entry in blacklisted_ips]

                cursor.executemany("""
                                   INSERT INTO blacklisted_ip_addresses (ip_address)
                                   VALUES (%s);
                                   """, blacklisted_ips)
                connection.commit()

        if signatures or yara_rules or blacklisted_ips:
            cursor.execute("""
                            INSERT INTO database_update_log (last_update)
                            VALUES (CURRENT_TIMESTAMP);
                            """, )
            connection.commit()

        cursor.close()
        connection.close()
        sleep(3600)

def main():
    create_database()
    create_tables()

    update_database()

if __name__ == '__main__':
    main()