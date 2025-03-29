CREATE TABLE IF NOT EXISTS blacklisted_ip_addresses(
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(39) NOT NULL
);

CREATE TABLE IF NOT EXISTS malware_signatures(
    id SERIAL PRIMARY KEY,
    signature VARCHAR(512) NOT NULL
);

CREATE TABLE IF NOT EXISTS yara_rules(
    id SERIAL PRIMARY KEY,
    rule VARCHAR(2500) NOT NULL
);

CREATE TABLE IF NOT EXISTS database_update_log(
    id SERIAL PRIMARY KEY,
    last_update TIMESTAMP NOT NULL
)