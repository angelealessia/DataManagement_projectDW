import requests
import pandas as pd
import gzip
import io
import os
from tqdm import tqdm

# EPSS
def download_epss():
    print("Downloading EPSS data...")
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    r = requests.get(url)
    with gzip.open(io.BytesIO(r.content)) as f:
        df = pd.read_csv(f, comment='#')
    df.to_csv("epss.csv", index=False)
    print(f"EPSS: {len(df)} records saved to epss.csv")

# NVD 
def download_nvd(years=range(2020, 2026)):
    print("Downloading NVD data...")
    all_cves = []
    for year in tqdm(years):
        url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
        r = requests.get(url)
        with gzip.open(io.BytesIO(r.content)) as f:
            data = pd.read_json(f)
        items = data["CVE_Items"]
        all_cves.extend(items)
    df = pd.json_normalize(all_cves)
    df.to_json("nvd_raw.json", orient="records")
    print(f"NVD: {len(df)} records saved to nvd_raw.json")

if __name__ == "__main__":
    download_epss()
    download_nvd()
