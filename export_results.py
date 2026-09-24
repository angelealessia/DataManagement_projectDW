#!/usr/bin/env python3
"""
Run every query in queries.sql and save its result as results/<Qn>.csv
(used for the charts and tables in the slides).

Usage:  python export_results.py
"""
import re
import warnings
from pathlib import Path

import pandas as pd
import psycopg2

DB_PARAMS = {"dbname": "vulnerabilities_dw", "user": "alessiaangele"}
warnings.filterwarnings("ignore", message=".*SQLAlchemy.*")  # psycopg2 works fine here

sql = Path("queries.sql").read_text()
# every query starts with a header line like "-- Q2a [DRILL-DOWN] ..."
blocks = re.split(r"(?m)^-- =+\n(?=-- Q)", sql)[1:]

out = Path("results")
out.mkdir(exist_ok=True)
conn = psycopg2.connect(**DB_PARAMS)
for block in blocks:
    header = block.splitlines()[0]
    qid = re.match(r"-- (Q\w+)", header).group(1)
    df = pd.read_sql_query(block, conn)
    df.to_csv(out / f"{qid}.csv", index=False)
    print(f"{qid:4} {len(df):3} rows  <- {header[3:].strip()}")
conn.close()
print(f"CSV files saved in {out.resolve()}")
