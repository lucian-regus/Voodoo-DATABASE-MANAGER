import os
import threading
import subprocess
import requests
import psycopg2
from time import sleep
from psycopg2 import sql
from dotenv import load_dotenv


NFT_FILE_PATH = "/var/lib/voodoo-av/blacklist.nft"
NFT_TABLE_NAME = "voodoo"
NFT_SET_NAME = "blacklist"
NFT_CHAIN_NAME = "output"

load_dotenv()

TARGET_DATABASE_NAME  = os.getenv('TARGET_DATABASE_NAME')
TARGET_API  = os.getenv('TARGET_API')

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

    quoted_dbname = sql.Identifier(TARGET_DATABASE_NAME)

    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (TARGET_DATABASE_NAME,))
    if not cursor.fetchone():
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(quoted_dbname))

    cursor.close()
    connection.close()

def create_tables():
    with open('schema.sql', 'r') as file:
        schema_sql = file.read()

    connection = create_connection(TARGET_DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute(schema_sql)

    cursor.close()
    connection.commit()
    connection.close()

def filter_entries(entries, field, deleted=False):
    return [(entry[field],) for entry in entries if entry.get("wasRemoved") is deleted]

def fetch_last_update(cursor):
    cursor.execute("SELECT last_update FROM database_update_log ORDER BY last_update DESC LIMIT 1;")

    return cursor.fetchone()

def build_update_url(last_update):
    if last_update:
        delta = last_update[0].strftime('%Y-%m-%dT%H:%M:%S.%f')
        return f"http://{TARGET_API}/api/database/updates?delta={delta}"

    return f"http://{TARGET_API}/api/database/updates"

def execute_batch(cursor, query, entries):
    if entries:
        cursor.executemany(query, entries)

def fetch_blacklisted_ips():
    connection = create_connection(TARGET_DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute('SELECT ip_address FROM blacklisted_ip_addresses;')
    ips = [row[0] for row in cursor.fetchall()]

    cursor.close()
    connection.close()

    return ips

def create_nft_file(ips):
    os.makedirs(os.path.dirname(NFT_FILE_PATH), exist_ok=True)

    with open(NFT_FILE_PATH, "w") as file:
        file.write(f"table inet {NFT_TABLE_NAME} {{\n")

        file.write(f"\tset {NFT_SET_NAME} {{\n")
        file.write("\t\ttype ipv4_addr;\n")
        file.write("\t\tflags interval;\n")
        if ips:
            file.write("\t\telements = {\n")
            for i, ip in enumerate(ips):
                comma = "," if i < len(ips) - 1 else ""
                file.write(f"\t\t\t{ip}{comma}\n")
            file.write("\t\t};\n")
        else:
            file.write("\t\telements = { };\n")
        file.write("\t}\n\n")

        file.write(f"\tchain {NFT_CHAIN_NAME} {{\n")
        file.write("\t\ttype filter hook output priority 0; policy accept;\n")
        file.write(f"\t\tip daddr @{NFT_SET_NAME} drop\n")
        file.write("\t}\n")

        file.write("}\n")

    print("[+] Updated the file")

def update_nft_file():
    blacklist = fetch_blacklisted_ips()

    create_nft_file(blacklist)

    subprocess.run(["nft", "flush", "ruleset"])
    subprocess.run(["nft", "-f", "/var/lib/voodoo-av/blacklist.nft"])

def update_database():
    while True:
        print('[+] STARTED')

        connection = create_connection(TARGET_DATABASE_NAME)
        cursor = connection.cursor()

        last_update = fetch_last_update(cursor)
        url = build_update_url(last_update)

        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"[!] Error fetching data: {e}")
            cursor.close()
            connection.close()
            sleep(3600)
            continue

        data = response.json()
        signatures = data.get("malwareSignatures", [])
        yara_rules = data.get("yaraRules", [])
        blacklisted_ips = data.get("blacklistedIpAddresses", [])

        new_signatures = filter_entries(signatures, "signature")
        to_remove_signatures = filter_entries(signatures, "signature", deleted=True)

        new_yara_rules = filter_entries(yara_rules, "rule")
        to_remove_yara_rules = filter_entries(yara_rules, "rule", deleted=True)

        new_blacklisted_ips = filter_entries(blacklisted_ips, "ipAddress")
        to_remove_blacklisted_ips = filter_entries(blacklisted_ips, "ipAddress", deleted=True)

        execute_batch(cursor, "DELETE FROM malware_signatures WHERE signature = %s;", to_remove_signatures)
        execute_batch(cursor, "DELETE FROM yara_rules WHERE rule = %s;", to_remove_yara_rules)
        execute_batch(cursor, "DELETE FROM blacklisted_ip_addresses WHERE ip_address = %s;", to_remove_blacklisted_ips)

        execute_batch(cursor, "INSERT INTO malware_signatures (signature) VALUES (%s);", new_signatures)
        execute_batch(cursor, "INSERT INTO yara_rules (rule) VALUES (%s);", new_yara_rules)
        execute_batch(cursor, "INSERT INTO blacklisted_ip_addresses (ip_address) VALUES (%s);", new_blacklisted_ips)

        if signatures or yara_rules or blacklisted_ips:
            cursor.execute("INSERT INTO database_update_log (last_update) VALUES (CURRENT_TIMESTAMP);")
            connection.commit()

        if new_blacklisted_ips or to_remove_blacklisted_ips:
             threading.Thread(target=update_nft_file, daemon=True).start()

        print('[+] ENDED')
        cursor.close()
        connection.close()
        sleep(3600)

def main():
    create_database()
    create_tables()

    update_database()

if __name__ == '__main__':
    main()