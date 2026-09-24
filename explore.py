import pandas as pd

print("=== NVD CVE Records ===")
df = pd.read_csv("nvd_cve_records.csv", nrows=5)
print(df.columns.tolist())
print(df.head(2))

print("\n=== EPSS ===")
epss = pd.read_csv("first_epss_current.csv", nrows=5)
print(epss.columns.tolist())
print(epss.head(2))

print("\n=== CWE Weaknesses ===")
cwe = pd.read_csv("nvd_cve_weaknesses.csv", nrows=5)
print(cwe.columns.tolist())
print(cwe.head(2))
