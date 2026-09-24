import pandas as pd
import psycopg2
from psycopg2.extras import execute_values

conn = psycopg2.connect(dbname="vulnerabilities_dw", user="alessiaangele")
cur = conn.cursor()

# tabelle

cur.execute("""
CREATE TABLE IF NOT EXISTS dim_time (
    time_id SERIAL PRIMARY KEY,
    published_date DATE,
    year INT,
    month INT,
    day INT,
    quarter INT
);

CREATE TABLE IF NOT EXISTS dim_severity (
    severity_id SERIAL PRIMARY KEY,
    level VARCHAR(20),
    attack_vector VARCHAR(50),
    attack_complexity VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS dim_cwe (
    cwe_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    category VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS dim_exploit_type (
    exploit_type_id SERIAL PRIMARY KEY,
    has_rce BOOLEAN,
    has_xss BOOLEAN,
    has_sql_injection BOOLEAN,
    has_buffer_overflow BOOLEAN
);

CREATE TABLE IF NOT EXISTS dim_vendor (
    vendor_id SERIAL PRIMARY KEY,
    vendor VARCHAR(200),
    product VARCHAR(200),
    vuln_name VARCHAR(500),
    kev_date_added DATE
);

CREATE TABLE IF NOT EXISTS fact_vulnerability (
    cve_id VARCHAR(30) PRIMARY KEY,
    time_id INT REFERENCES dim_time(time_id),
    severity_id INT REFERENCES dim_severity(severity_id),
    cwe_id VARCHAR(20) REFERENCES dim_cwe(cwe_id),
    exploit_type_id INT REFERENCES dim_exploit_type(exploit_type_id),
    vendor_id INT REFERENCES dim_vendor(vendor_id),
    cvss_score FLOAT,
    epss_score FLOAT,
    epss_percentile FLOAT,
    is_known_exploited BOOLEAN
);
""")
conn.commit()
print("Tabelle create.")

#data

print("Caricamento CSV...")
df = pd.read_csv("nvd_cve_records.csv", low_memory=False)
cwe_df = pd.read_csv("nvd_cve_weaknesses.csv")

# prendo solo il CWE primario per ogni CVE
cwe_primary = cwe_df[cwe_df["weakness_type"] == "Primary"].drop_duplicates("cve_id")
df = df.merge(cwe_primary[["cve_id","cwe_id"]], on="cve_id", how="left")

df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")

print(f"Record totali: {len(df)}")

# DIM_TIME
print("Popolo dim_time...")
dates = df[["published_date"]].dropna().drop_duplicates()
dates["year"]    = dates["published_date"].dt.year
dates["month"]   = dates["published_date"].dt.month
dates["day"]     = dates["published_date"].dt.day
dates["quarter"] = dates["published_date"].dt.quarter

execute_values(cur,
    "INSERT INTO dim_time (published_date, year, month, day, quarter) VALUES %s ON CONFLICT DO NOTHING",
    [tuple(r) for r in dates.itertuples(index=False)])
conn.commit()

# mappa data -> time_id
cur.execute("SELECT time_id, published_date FROM dim_time")
time_map = {str(r[1]): r[0] for r in cur.fetchall()}

# DIM_SEVERITY 
print("Popolo dim_severity...")
sev_cols = ["best_cvss_base_severity","cvss_v31_attack_vector","cvss_v31_attack_complexity"]
sevs = df[sev_cols].drop_duplicates().fillna("UNKNOWN")
execute_values(cur,
    "INSERT INTO dim_severity (level, attack_vector, attack_complexity) VALUES %s ON CONFLICT DO NOTHING",
    [tuple(r) for r in sevs.itertuples(index=False)])
conn.commit()

cur.execute("SELECT severity_id, level, attack_vector, attack_complexity FROM dim_severity")
sev_map = {(r[1],r[2],r[3]): r[0] for r in cur.fetchall()}

# DIM_CWE 
print("Popolo dim_cwe...")
cwes = df[["cwe_id"]].dropna().drop_duplicates()
cwes["description"] = ""
cwes["category"] = ""
execute_values(cur,
    "INSERT INTO dim_cwe (cwe_id, description, category) VALUES %s ON CONFLICT DO NOTHING",
    [tuple(r) for r in cwes.itertuples(index=False)])
conn.commit()

# DIM_EXPLOIT_TYPE 
print("Popolo dim_exploit_type...")
exp_cols = ["mentions_rce","mentions_xss","mentions_sql_injection","mentions_buffer_overflow"]
exps = df[exp_cols].drop_duplicates().fillna(False)
execute_values(cur,
    "INSERT INTO dim_exploit_type (has_rce, has_xss, has_sql_injection, has_buffer_overflow) VALUES %s ON CONFLICT DO NOTHING",
    [tuple(r) for r in exps.itertuples(index=False)])
conn.commit()

cur.execute("SELECT exploit_type_id, has_rce, has_xss, has_sql_injection, has_buffer_overflow FROM dim_exploit_type")
exp_map = {(r[1],r[2],r[3],r[4]): r[0] for r in cur.fetchall()}

# DIM_VENDOR
print("Popolo dim_vendor...")
ven_cols = ["kev_vendorproject","kev_product","kev_vulnerabilityname","kev_dateadded"]
vens = df[ven_cols].dropna(subset=["kev_vendorproject"]).drop_duplicates()
vens["kev_dateadded"] = pd.to_datetime(vens["kev_dateadded"], errors="coerce").dt.date
execute_values(cur,
    "INSERT INTO dim_vendor (vendor, product, vuln_name, kev_date_added) VALUES %s ON CONFLICT DO NOTHING",
    [tuple(r) for r in vens.itertuples(index=False)])
conn.commit()

cur.execute("SELECT vendor_id, vendor, product FROM dim_vendor")
ven_map = {(r[1],r[2]): r[0] for r in cur.fetchall()}

# FACT_VULNERABILITY 
print("Popolo fact_vulnerability...")

def get_time_id(row):
    d = str(row["published_date"])[:10] if pd.notna(row["published_date"]) else None
    return time_map.get(d)

def get_sev_id(row):
    key = (
        row.get("best_cvss_base_severity","UNKNOWN") or "UNKNOWN",
        row.get("cvss_v31_attack_vector","UNKNOWN") or "UNKNOWN",
        row.get("cvss_v31_attack_complexity","UNKNOWN") or "UNKNOWN"
    )
    return sev_map.get(key)

def get_exp_id(row):
    key = (
        bool(row.get("mentions_rce",False)),
        bool(row.get("mentions_xss",False)),
        bool(row.get("mentions_sql_injection",False)),
        bool(row.get("mentions_buffer_overflow",False))
    )
    return exp_map.get(key)

def get_ven_id(row):
    key = (row.get("kev_vendorproject"), row.get("kev_product"))
    return ven_map.get(key)

rows = []
for _, row in df.iterrows():
    rows.append((
        row["cve_id"],
        get_time_id(row),
        get_sev_id(row),
        row.get("cwe_id") if pd.notna(row.get("cwe_id","")) else None,
        get_exp_id(row),
        get_ven_id(row),
        row.get("best_cvss_base_score"),
        row.get("epss_score"),
        row.get("epss_percentile"),
        bool(row.get("kev_is_known_exploited", False))
    ))

execute_values(cur,
    """INSERT INTO fact_vulnerability
       (cve_id, time_id, severity_id, cwe_id, exploit_type_id, vendor_id,
        cvss_score, epss_score, epss_percentile, is_known_exploited)
       VALUES %s ON CONFLICT DO NOTHING""",
    rows, page_size=1000)
conn.commit()

cur.close()
conn.close()
print("ETL completato!")
