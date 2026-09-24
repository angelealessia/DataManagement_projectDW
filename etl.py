#!/usr/bin/env python3
"""
ETL - CVE Data Warehouse
Data Management 2025/2026 - Alessia Angele (2003000)

The sources are integrated HERE, starting from the separate files of each
provider (the pre-joined columns of nvd_cve_records.csv are used only as a
cross-check, never as input):

  Source        Provider   File
  ------------  ---------  ------------------------------------------------
  NVD records   NIST       nvd_cve_records.csv
  NVD CWE       NIST       nvd_cve_weaknesses.csv
  NVD CPE       NIST       nvd_cve_cpe_matches.csv
  EPSS          FIRST      first_epss_current.csv
  KEV catalog   CISA       cisa_kev_catalog.csv
  CWE catalog   MITRE      cwe_1000.csv   (optional, view 1000 "Research Concepts")

Target: two star schemas sharing the conformed dimensions
dim_date, dim_product, dim_cwe.

  fact_vulnerability   grain: one CVE published in NVD
  fact_kev_addition    grain: one CVE added to the CISA KEV catalog

Usage:
  python etl.py                 # full run, (re)creates and loads the DW
  python etl.py --dry-run       # transformations + report only, no database
  python etl.py --data-dir data # CSV files in another folder
"""
import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

DB_PARAMS = {"dbname": "vulnerabilities_dw", "user": "alessiaangele"}
UNKNOWN = -1  # surrogate key of the "Unknown" member of every dimension

EXPLOIT_PATTERNS = {   # applied to the lower-cased NVD description
    "f_rce": r"remote code execution|execut\w* arbitrary (?:code|commands?)|arbitrary code execution"
             r"|\brce\b|os command injection|command injection|code injection",
    "f_xss": r"cross[- ]site scripting|\bxss\b",
    "f_sqli": r"sql injection|\bsqli\b",
    "f_bof": r"buffer overflow|stack[- ]based overflow|heap[- ]based overflow|buffer overrun",
}

REPORT = {"rows_read": {}, "cleaning": {}, "integration": {},
          "validation": {}, "dimensions": {}, "facts": {}}


# =============================================================================
# Helpers
# =============================================================================
def _norm(col):
    """'kev_dateAdded' -> 'kevdateadded': makes column lookup case/format independent."""
    return re.sub(r"[^a-z0-9]", "", str(col).lower())


def load_csv(data_dir, fname, spec, source, required=True):
    """Read only the needed columns, renamed to logical names.

    spec = {logical_name: ([candidate normalized names], required?)}
    Stops with a clear message if a required column is missing.
    """
    path = data_dir / fname
    if not path.exists():
        if required:
            sys.exit(f"[ERROR] missing file: {path}")
        print(f"  - {fname}: not found, skipped (optional)")
        return None
    header = pd.read_csv(path, nrows=0).columns
    by_norm = {_norm(c): c for c in header}
    usecols, rename = [], {}
    for logical, (cands, req) in spec.items():
        orig = next((by_norm[c] for c in cands if c in by_norm), None)
        if orig is None:
            if req:
                sys.exit(f"[ERROR] {fname}: column '{logical}' not found "
                         f"(looked for {cands}).\nAvailable columns: {list(header)}")
            continue
        if orig not in usecols:
            usecols.append(orig)
            rename[orig] = logical
    # index_col=False: MITRE's CSV ends every row with a trailing comma, which
    # would otherwise make pandas shift all columns by one position
    df = (pd.read_csv(path, usecols=usecols, dtype=str, low_memory=False, index_col=False)
            .rename(columns=rename))
    REPORT["rows_read"][source] = len(df)
    print(f"  - {fname}: {len(df):,} rows")
    return df


def clean_cve_id(s):
    return s.astype(str).str.strip().str.upper()


def keep_valid_cves(df, source):
    """Drop malformed CVE ids and duplicated rows; log how many."""
    n0 = len(df)
    df = df[df["cve_id"].str.match(r"^CVE-\d{4}-\d{4,}$", na=False)]
    n_bad = n0 - len(df)
    n_dup = int(df["cve_id"].duplicated().sum())
    df = df.drop_duplicates("cve_id")
    REPORT["cleaning"][f"{source}: malformed cve_id dropped"] = n_bad
    REPORT["cleaning"][f"{source}: duplicate cve_id dropped"] = n_dup
    return df


def clean_float(s, lo, hi, name):
    """Parse a numeric column. Empty cells, 'NaN' text, +/-Infinity (IEEE 754
    special values) and out-of-range values all become NULL, so no NaN ever
    reaches PostgreSQL (a float NaN there breaks AVG/ORDER BY)."""
    raw = pd.to_numeric(s, errors="coerce")
    n_empty = int(s.isna().sum())
    n_text = int((s.notna() & raw.isna()).sum())        # 'NaN', garbage
    n_inf = int(np.isinf(raw).sum())
    x = raw.replace([np.inf, -np.inf], np.nan)
    bad = x.notna() & ((x < lo) | (x > hi))
    x = x.mask(bad)
    REPORT["cleaning"][name] = {
        "empty_or_NaN": n_empty, "non_numeric_text": n_text,
        "infinite": n_inf, "out_of_range": int(bad.sum()),
        "valid": int(x.notna().sum())}
    return x


def to_bool(s):
    """Robust boolean parsing: NaN -> False (Python's bool(NaN) would be True)."""
    return s.astype(str).str.strip().str.lower().isin(
        ["true", "t", "1", "1.0", "yes", "y"])


def norm_name(s):
    """'Palo Alto Networks' -> 'palo_alto_networks' (same convention as CPE names)."""
    out = (s.fillna("").astype(str).str.strip().str.lower()
             .str.replace("\\", "", regex=False)
             .str.replace(r"[^a-z0-9]+", "_", regex=True).str.strip("_"))
    return out.replace("", np.nan)


def to_day(s):
    """Timestamp string -> calendar day (time part removed: grain of dim_date)."""
    try:
        d = pd.to_datetime(s, errors="coerce", utc=True, format="mixed")
    except (TypeError, ValueError):
        d = pd.to_datetime(s, errors="coerce", utc=True)
    return d.dt.tz_localize(None).dt.normalize()


def date_key(d):
    """Calendar day -> smart key YYYYMMDD; missing date -> Unknown member."""
    k = d.dt.year * 10000 + d.dt.month * 100 + d.dt.day
    return k.fillna(UNKNOWN).astype(int)


def add_surrogate(df, key):
    df = df.reset_index(drop=True)
    df.insert(0, key, np.arange(1, len(df) + 1))
    return df


# =============================================================================
# 1. EXTRACT
# =============================================================================
def extract(data_dir):
    print("[1/5] Extract")
    rec = load_csv(data_dir, "nvd_cve_records.csv", {
        "cve_id": (["cveid"], True),
        "published": (["publisheddate", "published"], True),
        "cvss_score": (["bestcvssbasescore"], True),
        "severity": (["bestcvssbaseseverity"], True),
        "attack_vector": (["cvssv31attackvector"], False),
        "attack_complexity": (["cvssv31attackcomplexity"], False),
        # English description: the attack-class flags are computed from it here.
        # (The Kaggle mentions_* flags leak the KEV label - 1,036/1,039 KEV CVEs
        #  flagged RCE, 0 SQLi/XSS - so they are only compared, never used.)
        "description": (["description", "descriptionen", "englishdescription",
                         "cvedescription", "summary"], True),
        "kg_rce": (["mentionsrce"], False),
        "kg_xss": (["mentionsxss"], False),
        "kg_sqli": (["mentionssqlinjection"], False),
        "kg_bof": (["mentionsbufferoverflow"], False),
        # pre-joined by the Kaggle author: used ONLY to cross-check our joins
        "chk_kev": (["kevisknownexploited"], False),
        "chk_epss": (["epssscore"], False),
    }, "NVD records")

    cwe = load_csv(data_dir, "nvd_cve_weaknesses.csv", {
        "cve_id": (["cveid"], True),
        "cwe_id": (["cweid", "cwe"], True),
        "wtype": (["weaknesstype", "type"], False),
        "wsource": (["source", "weaknesssource"], False),
    }, "NVD weaknesses")

    cpe = load_csv(data_dir, "nvd_cve_cpe_matches.csv", {
        "cve_id": (["cveid"], True),
        "criteria": (["criteria", "cpecriteria", "cpe23uri", "cpeuri",
                      "cpename", "cpe"], False),
        "vendor": (["vendor", "cpevendor"], False),
        "product": (["product", "cpeproduct"], False),
        "part": (["part", "cpepart"], False),
        "vulnerable": (["vulnerable", "isvulnerable"], False),
    }, "NVD CPE matches")

    epss = load_csv(data_dir, "first_epss_current.csv", {
        "cve_id": (["cve", "cveid"], True),
        "epss": (["epss", "epssscore"], True),
        "percentile": (["percentile", "epsspercentile"], True),
    }, "FIRST EPSS")

    kev = load_csv(data_dir, "cisa_kev_catalog.csv", {
        "cve_id": (["cveid", "cve"], True),
        "vendor": (["vendorproject", "vendor"], True),
        "product": (["product"], True),
        "date_added": (["dateadded"], True),
        "due_date": (["duedate"], False),
        "ransomware": (["knownransomwarecampaignuse"], False),
    }, "CISA KEV")

    mitre = load_csv(data_dir, "cwe_1000.csv", {
        "cwe_num": (["cweid"], True),
        "name": (["name"], True),
        "abstraction": (["weaknessabstraction", "abstraction"], False),
        "related": (["relatedweaknesses"], False),
    }, "MITRE CWE", required=False)

    return rec, cwe, cpe, epss, kev, mitre


# =============================================================================
# 2. TRANSFORM - clean each source
# =============================================================================
def transform_records(rec):
    rec["cve_id"] = clean_cve_id(rec["cve_id"])
    rec = keep_valid_cves(rec, "NVD records")
    rec["published_day"] = to_day(rec["published"])
    REPORT["cleaning"]["NVD records: unparseable published date"] = \
        int(rec["published_day"].isna().sum())

    rec["cvss_score"] = clean_float(rec["cvss_score"], 0, 10, "cvss_score")
    rec["severity"] = rec["severity"].str.strip().str.upper().fillna("UNKNOWN")
    for c in ("attack_vector", "attack_complexity"):
        rec[c] = (rec[c].str.strip().str.upper().fillna("UNKNOWN")
                  if c in rec else "UNKNOWN")
    # attack-class flags by keyword matching on the NVD description only
    desc = rec["description"].fillna("").str.lower()
    for f, pat in EXPLOIT_PATTERNS.items():
        rec[f] = desc.str.contains(pat, regex=True)
    REPORT["cleaning"]["CVEs without description"] = int((desc == "").sum())
    REPORT["integration"]["attack-class flags from NVD description"] = {
        f: {"ours": int(rec[f].sum()),
            "kaggle": int(to_bool(rec["kg" + f[1:]]).sum()) if "kg" + f[1:] in rec else None}
        for f in EXPLOIT_PATTERNS}

    # informative consistency check: severity label vs CVSS v3 score bands
    band = pd.cut(rec["cvss_score"], [-0.01, 0, 3.9, 6.9, 8.9, 10],
                  labels=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).astype(str)
    mism = rec["cvss_score"].notna() & (rec["severity"] != "UNKNOWN") & (band != rec["severity"])
    REPORT["validation"]["severity label != CVSS v3 band (expected for CVSS v2-only CVEs)"] = int(mism.sum())
    return rec


def transform_epss(epss):
    epss["cve_id"] = clean_cve_id(epss["cve_id"])
    epss = keep_valid_cves(epss, "EPSS")
    epss["epss"] = clean_float(epss["epss"], 0, 1, "epss_score")
    epss["percentile"] = clean_float(epss["percentile"], 0, 1, "epss_percentile")
    return epss[["cve_id", "epss", "percentile"]]


def transform_cwe(cwe):
    """One primary CWE per CVE: prefer weakness_type = Primary, then NVD as source."""
    cwe["cve_id"] = clean_cve_id(cwe["cve_id"])
    # 'cwe-79 ' -> 'CWE-79'; NVD placeholders (NVD-CWE-noinfo/Other) kept as they are
    cwe["cwe_id"] = cwe["cwe_id"].str.strip().str.replace(r"^(?i:cwe)-", "CWE-", regex=True)
    cwe = cwe[cwe["cwe_id"].notna() & (cwe["cwe_id"] != "")].copy()
    cwe["_p1"] = (cwe["wtype"].str.lower() != "primary").astype(int) if "wtype" in cwe else 0
    cwe["_p2"] = (~cwe["wsource"].fillna("").str.contains("nist", case=False)).astype(int) \
        if "wsource" in cwe else 0
    prim = (cwe.sort_values(["cve_id", "_p1", "_p2", "cwe_id"])
               .drop_duplicates("cve_id")[["cve_id", "cwe_id"]])
    REPORT["integration"]["CVEs with more than one CWE (primary chosen)"] = \
        int((cwe.groupby("cve_id").size() > 1).sum())
    return prim


def transform_cpe(cpe):
    """Parse CPE 2.3 strings -> (part, vendor, product), keep vulnerable matches only,
    choose one primary product per CVE (most frequent vendor/product pair)."""
    cpe["cve_id"] = clean_cve_id(cpe["cve_id"])
    if "vulnerable" in cpe:
        vul = to_bool(cpe["vulnerable"])
        REPORT["cleaning"]["CPE: non-vulnerable platform rows dropped"] = int((~vul).sum())
        cpe = cpe[vul].copy()
    if "criteria" in cpe:
        # cpe:2.3:<part>:<vendor>:<product>:<version>:...
        parts = cpe["criteria"].str.split(":", n=6, expand=True)
        if parts.shape[1] < 5:
            sys.exit("[ERROR] CPE criteria column is not in CPE 2.3 format")
        cpe["part"], cpe["vendor"], cpe["product"] = parts[2], parts[3], parts[4]
    elif not {"vendor", "product"} <= set(cpe.columns):
        sys.exit("[ERROR] CPE file: need either a CPE criteria column or vendor+product")
    if "part" not in cpe:
        cpe["part"] = "?"
    cpe["vendor"] = norm_name(cpe["vendor"])
    cpe["product"] = norm_name(cpe["product"])
    n0 = len(cpe)
    cpe = cpe[cpe["vendor"].notna() & cpe["product"].notna()]
    REPORT["cleaning"]["CPE: rows with wildcard/empty vendor or product dropped"] = n0 - len(cpe)

    cnt = (cpe.groupby(["cve_id", "vendor", "product"], sort=False)
              .agg(n=("cve_id", "size"), part=("part", "first")).reset_index())
    affected = cnt.groupby("cve_id").size().rename("affected_products").reset_index()
    primary = (cnt.sort_values(["cve_id", "n", "vendor", "product"],
                               ascending=[True, False, True, True])
                  .drop_duplicates("cve_id")[["cve_id", "vendor", "product", "part"]])
    return cnt, primary, affected


def transform_kev(kev, cnt):
    """Clean the CISA catalog and reconcile CISA vendor names with NVD CPE names
    (entity resolution), so that dim_product is conformed across both facts."""
    kev["cve_id"] = clean_cve_id(kev["cve_id"])
    kev = keep_valid_cves(kev, "KEV").copy()
    kev["kev_vendor"] = norm_name(kev["vendor"]).fillna("unknown")
    kev["kev_product"] = norm_name(kev["product"]).fillna("unknown")
    kev["date_added_day"] = to_day(kev["date_added"])
    kev["due_day"] = to_day(kev["due_date"]) if "due_date" in kev else pd.NaT
    kev["is_ransomware"] = (kev["ransomware"].str.strip().str.lower().eq("known")
                            if "ransomware" in kev else False)

    # --- vendor reconciliation: CISA name -> NVD CPE vendor --------------------
    cand = (cnt[["cve_id", "vendor"]].drop_duplicates()
              .merge(kev[["cve_id", "kev_vendor"]], on="cve_id"))
    votes = cand.groupby(["kev_vendor", "vendor"]).size().rename("n").reset_index()
    tot = cand.groupby("kev_vendor")["cve_id"].nunique().rename("tot").reset_index()
    votes = votes.merge(tot, on="kev_vendor")
    exact = set(votes.loc[votes["kev_vendor"] == votes["vendor"], "kev_vendor"])
    best = (votes[~votes["kev_vendor"].isin(exact) & (votes["n"] / votes["tot"] >= 0.5)]
              .sort_values(["kev_vendor", "n", "vendor"], ascending=[True, False, True])
              .drop_duplicates("kev_vendor"))
    vmap = {v: v for v in exact}
    vmap.update(dict(zip(best["kev_vendor"], best["vendor"])))
    kev["vendor_c"] = kev["kev_vendor"].map(vmap).fillna(kev["kev_vendor"])

    all_kev_vendors = set(kev["kev_vendor"])
    remapped = {k: v for k, v in vmap.items() if k != v}
    REPORT["integration"]["KEV vendor names"] = {
        "distinct": len(all_kev_vendors),
        "identical to NVD CPE name": len(exact),
        "remapped to NVD CPE name": len(remapped),
        "kept as in CISA (no NVD evidence)": len(all_kev_vendors) - len(exact) - len(remapped),
        "examples": dict(sorted(remapped.items())[:15]),
    }

    # --- product: most frequent CPE product of the reconciled vendor ------------
    kp = (kev[["cve_id", "vendor_c"]]
          .merge(cnt, left_on=["cve_id", "vendor_c"], right_on=["cve_id", "vendor"])
          .sort_values(["cve_id", "n", "product"], ascending=[True, False, True])
          .drop_duplicates("cve_id")[["cve_id", "product", "part"]]
          .rename(columns={"product": "product_c"}))
    kev = kev.merge(kp, on="cve_id", how="left")
    kev["product_c"] = kev["product_c"].fillna(kev["kev_product"])
    kev["part"] = kev["part"].fillna("?")
    return kev


# =============================================================================
# 3. TRANSFORM - build dimensions
# =============================================================================
def build_dim_date(*day_series):
    days = pd.concat([s.dropna() for s in day_series])
    rng = pd.date_range(days.min(), days.max(), freq="D")
    d = pd.DataFrame({"full_date": rng})
    d.insert(0, "date_key", date_key(d["full_date"]))
    d["day"] = rng.day
    d["month"] = rng.month
    d["month_name"] = rng.month_name()
    d["quarter"] = rng.quarter
    d["year"] = rng.year
    d["year_month"] = rng.strftime("%Y-%m")
    d["year_quarter"] = d["year"].astype(str) + "-Q" + d["quarter"].astype(str)
    d["day_of_week"] = rng.day_name()
    d["is_weekend"] = rng.dayofweek >= 5
    d["full_date"] = rng.date
    unk = pd.DataFrame([{"date_key": UNKNOWN, "full_date": None, "day": None,
                         "month": None, "month_name": "Unknown", "quarter": None,
                         "year": None, "year_month": "Unknown", "year_quarter": "Unknown",
                         "day_of_week": "Unknown", "is_weekend": None}])
    return pd.concat([unk, d], ignore_index=True)


def build_dim_product(primary, kev):
    p = pd.concat([
        primary[["vendor", "product", "part"]],
        kev[["vendor_c", "product_c", "part"]].rename(
            columns={"vendor_c": "vendor", "product_c": "product"}),
    ]).drop_duplicates(["vendor", "product"]).sort_values(["vendor", "product"])
    p["product_type"] = p["part"].map(
        {"a": "application", "o": "operating_system", "h": "hardware"}).fillna("unknown")
    p = add_surrogate(p[["vendor", "product", "product_type"]], "product_key")
    unk = pd.DataFrame([{"product_key": UNKNOWN, "vendor": "unknown",
                         "product": "unknown", "product_type": "unknown"}])
    return pd.concat([unk, p], ignore_index=True)


def build_dim_cwe(cwe_ids, mitre):
    d = pd.DataFrame({"cwe_id": sorted(set(cwe_ids))})
    names, abstr, parent = {}, {}, {}
    if mitre is not None:
        m = mitre.copy()
        m["cwe_id"] = "CWE-" + m["cwe_num"].str.strip()
        names = dict(zip(m["cwe_id"], m["name"]))
        if "abstraction" in m:
            abstr = dict(zip(m["cwe_id"], m["abstraction"]))
        if "related" in m:
            pat = re.compile(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000(?::ORDINAL:(\w+))?")
            for cid, rel in zip(m["cwe_id"], m["related"].fillna("")):
                hits = pat.findall(rel)
                if hits:
                    prim = [h for h, o in hits if o == "Primary"]
                    parent[cid] = "CWE-" + (prim or [hits[0][0]])[0]

    def pillar_of(c):
        seen = set()
        while c in parent and c not in seen:  # walk ChildOf up to the root (Pillar)
            seen.add(c)
            c = parent[c]
        return c

    special = d["cwe_id"].str.startswith("NVD-CWE")
    known = d["cwe_id"].isin(names)
    d["cwe_name"] = d["cwe_id"].map(names)
    d.loc[d["cwe_id"] == "NVD-CWE-noinfo", "cwe_name"] = "Insufficient information (NVD)"
    d.loc[d["cwe_id"] == "NVD-CWE-Other", "cwe_name"] = "Other (NVD)"
    d["abstraction"] = d["cwe_id"].map(abstr)
    d["pillar_id"] = np.where(known, d["cwe_id"].map(pillar_of), None)
    d["pillar_name"] = d["pillar_id"].map(names)
    d.loc[special, "pillar_name"] = "Not classified (NVD)"
    d.loc[~special & ~known, "pillar_name"] = "Not in MITRE view 1000"
    REPORT["integration"]["CWE ids enriched from MITRE catalog"] = \
        f"{int(known.sum())}/{len(d)}" if mitre is not None else "MITRE file not provided"

    d = add_surrogate(d, "cwe_key")
    unk = pd.DataFrame([{"cwe_key": UNKNOWN, "cwe_id": "UNKNOWN", "cwe_name": "Unknown",
                         "abstraction": None, "pillar_id": None, "pillar_name": "Unknown"}])
    return pd.concat([unk, d], ignore_index=True)


def build_dim_severity(rec):
    d = (rec[["severity", "attack_vector", "attack_complexity"]].drop_duplicates()
           .sort_values(["severity", "attack_vector", "attack_complexity"]))
    return add_surrogate(d.rename(columns={"severity": "severity_level"}), "severity_key")


def build_dim_exploit_type(rec):
    d = (rec[["f_rce", "f_xss", "f_sqli", "f_bof"]].drop_duplicates()
           .sort_values(["f_rce", "f_sqli", "f_xss", "f_bof"], ascending=False))
    # documented precedence rule for a single label: RCE > SQLi > XSS > BoF
    d["primary_class"] = np.select(
        [d["f_rce"], d["f_sqli"], d["f_xss"], d["f_bof"]],
        ["RCE", "SQL Injection", "XSS", "Buffer Overflow"], default="None")
    d["n_keywords"] = d[["f_rce", "f_xss", "f_sqli", "f_bof"]].sum(axis=1)
    return add_surrogate(d, "exploit_type_key")


# =============================================================================
# 4. TRANSFORM - build facts
# =============================================================================
def build_facts(rec, epss, cwe_primary, primary, affected, kev,
                dim_product, dim_cwe, dim_sev, dim_exp):
    prod_key = dim_product.set_index(["vendor", "product"])["product_key"]
    cwe_key = dict(zip(dim_cwe["cwe_id"], dim_cwe["cwe_key"]))

    # Source precedence: for CVEs in KEV, CISA's vendor attribution wins over the
    # CPE heuristic, so the same CVE has the same product in both facts.
    kev_prod = kev[["cve_id", "vendor_c", "product_c"]].rename(
        columns={"vendor_c": "vendor", "product_c": "product"})
    prim = primary[["cve_id", "vendor", "product"]]
    changed = prim.merge(kev_prod, on="cve_id", suffixes=("", "_kev"))
    REPORT["integration"]["KEV CVEs whose product was set from CISA (differs from CPE primary)"] = \
        int(((changed["vendor"] != changed["vendor_kev"]) |
             (changed["product"] != changed["product_kev"])).sum())
    prim = pd.concat([kev_prod[kev_prod["cve_id"].isin(rec["cve_id"])],
                      prim[~prim["cve_id"].isin(kev_prod["cve_id"])]])

    # ---------------- fact_vulnerability ----------------
    f = (rec.merge(epss, on="cve_id", how="left")
            .merge(cwe_primary, on="cve_id", how="left")
            .merge(prim, on="cve_id", how="left")
            .merge(affected, on="cve_id", how="left"))
    f["published_date_key"] = date_key(f["published_day"])
    f["product_key"] = [prod_key.get((v, p), UNKNOWN)
                        for v, p in zip(f["vendor"], f["product"])]
    f["cwe_key"] = f["cwe_id"].map(cwe_key).fillna(UNKNOWN).astype(int)
    f = f.merge(dim_sev.rename(columns={"severity_level": "severity"}),
                on=["severity", "attack_vector", "attack_complexity"], how="left")
    f = f.merge(dim_exp[["exploit_type_key", "f_rce", "f_xss", "f_sqli", "f_bof"]],
                on=["f_rce", "f_xss", "f_sqli", "f_bof"], how="left")
    f["is_in_kev"] = f["cve_id"].isin(kev["cve_id"])
    f["affected_products"] = f["affected_products"].fillna(0).astype(int)
    # sanity check against label leakage: KEV CVEs per attack flag
    REPORT["validation"]["KEV CVEs per attack flag (ours)"] = {
        fl: int((f["is_in_kev"] & f[fl]).sum()) for fl in EXPLOIT_PATTERNS}

    # cross-checks against the columns pre-joined by the Kaggle author
    v = REPORT["validation"]
    v["EPSS matched by our join"] = int(f["epss"].notna().sum())
    if "chk_epss" in f:
        v["EPSS in pre-joined column (reference)"] = int(
            pd.to_numeric(f["chk_epss"], errors="coerce").notna().sum())
    v["KEV matched by our join"] = int(f["is_in_kev"].sum())
    if "chk_kev" in f:
        v["KEV flag disagreements with pre-joined column"] = int(
            (to_bool(f["chk_kev"]) != f["is_in_kev"]).sum())

    fact_v = f[["cve_id", "published_date_key", "product_key", "cwe_key",
                "severity_key", "exploit_type_key", "cvss_score", "epss",
                "percentile", "affected_products", "is_in_kev"]].rename(
        columns={"epss": "epss_score", "percentile": "epss_percentile"})

    # ---------------- fact_kev_addition ----------------
    k = (kev.merge(rec[["cve_id", "published_day"]], on="cve_id", how="left")
            .merge(cwe_primary, on="cve_id", how="left"))
    k["date_added_key"] = date_key(k["date_added_day"])
    k["due_date_key"] = date_key(k["due_day"])
    k["published_date_key"] = date_key(k["published_day"])
    k["product_key"] = [prod_key.get((v_, p), UNKNOWN)
                        for v_, p in zip(k["vendor_c"], k["product_c"])]
    k["cwe_key"] = k["cwe_id"].map(cwe_key).fillna(UNKNOWN).astype(int)
    k["in_nvd_snapshot"] = k["cve_id"].isin(rec["cve_id"])
    k["days_to_kev"] = (k["date_added_day"] - k["published_day"]).dt.days.astype("Int64")
    k["remediation_days"] = (k["due_day"] - k["date_added_day"]).dt.days.astype("Int64")
    v["KEV entries added before NVD publication (days_to_kev < 0)"] = \
        int((k["days_to_kev"] < 0).sum())
    v["KEV entries outside the NVD 2020-2026 snapshot"] = int((~k["in_nvd_snapshot"]).sum())

    fact_k = k[["cve_id", "date_added_key", "due_date_key", "published_date_key",
                "product_key", "cwe_key", "is_ransomware", "in_nvd_snapshot",
                "days_to_kev", "remediation_days"]]

    for name, fact, cols in (("fact_vulnerability", fact_v,
                              ["published_date_key", "product_key", "cwe_key"]),
                             ("fact_kev_addition", fact_k,
                              ["date_added_key", "product_key", "cwe_key"])):
        REPORT["facts"][name] = {"rows": len(fact), "rows pointing to Unknown member":
                                 {c: int((fact[c] == UNKNOWN).sum()) for c in cols}}
    return fact_v, fact_k


# =============================================================================
# 5. LOAD
# =============================================================================
DDL = """
DROP TABLE IF EXISTS fact_vulnerability, fact_kev_addition,
    dim_date, dim_time, dim_product, dim_vendor, dim_cwe,
    dim_severity, dim_exploit_type CASCADE;

CREATE TABLE dim_date (
    date_key      INT PRIMARY KEY,          -- YYYYMMDD, -1 = Unknown
    full_date     DATE UNIQUE,
    day           SMALLINT,
    month         SMALLINT,
    month_name    VARCHAR(12),
    quarter       SMALLINT,
    year          SMALLINT,
    year_month    VARCHAR(10),
    year_quarter  VARCHAR(10),
    day_of_week   VARCHAR(10),
    is_weekend    BOOLEAN
);

CREATE TABLE dim_product (
    product_key   INT PRIMARY KEY,
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    product_type  VARCHAR(20),              -- application / operating_system / hardware
    UNIQUE (vendor, product)
);

CREATE TABLE dim_cwe (
    cwe_key       INT PRIMARY KEY,
    cwe_id        VARCHAR(30) NOT NULL UNIQUE,
    cwe_name      TEXT,
    abstraction   VARCHAR(20),
    pillar_id     VARCHAR(30),
    pillar_name   TEXT
);

CREATE TABLE dim_severity (
    severity_key      INT PRIMARY KEY,
    severity_level    VARCHAR(10) NOT NULL,
    attack_vector     VARCHAR(30) NOT NULL,
    attack_complexity VARCHAR(10) NOT NULL,
    UNIQUE (severity_level, attack_vector, attack_complexity)
);

CREATE TABLE dim_exploit_type (
    exploit_type_key    INT PRIMARY KEY,
    has_rce             BOOLEAN NOT NULL,
    has_xss             BOOLEAN NOT NULL,
    has_sql_injection   BOOLEAN NOT NULL,
    has_buffer_overflow BOOLEAN NOT NULL,
    primary_class       VARCHAR(20) NOT NULL,
    n_keywords          SMALLINT NOT NULL,
    UNIQUE (has_rce, has_xss, has_sql_injection, has_buffer_overflow)
);

CREATE TABLE fact_vulnerability (
    cve_id             VARCHAR(30) PRIMARY KEY,           -- degenerate dimension
    published_date_key INT NOT NULL REFERENCES dim_date,
    product_key        INT NOT NULL REFERENCES dim_product,
    cwe_key            INT NOT NULL REFERENCES dim_cwe,
    severity_key       INT NOT NULL REFERENCES dim_severity,
    exploit_type_key   INT NOT NULL REFERENCES dim_exploit_type,
    cvss_score         NUMERIC(3,1),
    epss_score         NUMERIC(7,5),
    epss_percentile    NUMERIC(7,5),
    affected_products  INT NOT NULL,
    is_in_kev          BOOLEAN NOT NULL
);

CREATE TABLE fact_kev_addition (
    cve_id             VARCHAR(30) PRIMARY KEY,           -- degenerate dimension
    date_added_key     INT NOT NULL REFERENCES dim_date,  -- role: date added to KEV
    due_date_key       INT NOT NULL REFERENCES dim_date,  -- role: remediation due date
    published_date_key INT NOT NULL REFERENCES dim_date,  -- role: NVD publication date
    product_key        INT NOT NULL REFERENCES dim_product,
    cwe_key            INT NOT NULL REFERENCES dim_cwe,
    is_ransomware      BOOLEAN NOT NULL,
    in_nvd_snapshot    BOOLEAN NOT NULL,
    days_to_kev        INT,
    remediation_days   INT
);
"""

INDEXES = """
CREATE INDEX ON fact_vulnerability (published_date_key);
CREATE INDEX ON fact_vulnerability (product_key);
CREATE INDEX ON fact_vulnerability (cwe_key);
CREATE INDEX ON fact_vulnerability (severity_key);
CREATE INDEX ON fact_vulnerability (exploit_type_key);
CREATE INDEX ON fact_kev_addition (date_added_key);
CREATE INDEX ON fact_kev_addition (product_key);
CREATE INDEX ON fact_kev_addition (cwe_key);
"""

POST_CHECKS = {
    "dim_date rows = distinct dates + Unknown":
        "SELECT COUNT(*) = COUNT(DISTINCT full_date) + 1 FROM dim_date",
    "fact_vulnerability.is_in_kev = KEV rows in snapshot":
        "SELECT (SELECT COUNT(*) FROM fact_vulnerability WHERE is_in_kev) = "
        "(SELECT COUNT(*) FROM fact_kev_addition WHERE in_nvd_snapshot)",
    "no NaN in numeric measures":
        "SELECT COUNT(*) = 0 FROM fact_vulnerability "
        "WHERE cvss_score = 'NaN' OR epss_score = 'NaN' OR epss_percentile = 'NaN'",
}


def to_rows(df):
    """DataFrame -> list of tuples of plain Python values (NaN/NA/NaT -> None)."""
    out = []
    for r in df.itertuples(index=False, name=None):
        row = []
        for v in r:
            if v is None or v is pd.NA or v is pd.NaT or (isinstance(v, float) and np.isnan(v)):
                row.append(None)
            elif isinstance(v, np.generic):
                row.append(v.item())
            else:
                row.append(v)
        out.append(tuple(row))
    return out


def load(tables):
    import psycopg2
    from psycopg2.extras import execute_values

    print("[5/5] Load into PostgreSQL")
    conn = psycopg2.connect(**DB_PARAMS)
    try:
        with conn, conn.cursor() as cur:
            cur.execute(DDL)
            for name, df in tables.items():
                cols = ", ".join(df.columns)
                execute_values(cur, f"INSERT INTO {name} ({cols}) VALUES %s",
                               to_rows(df), page_size=5000)
                print(f"  - {name}: {len(df):,} rows")
            cur.execute(INDEXES)
        with conn.cursor() as cur:
            conn.autocommit = True
            cur.execute("ANALYZE")
            for label, sql in POST_CHECKS.items():
                cur.execute(sql)
                ok = cur.fetchone()[0]
                REPORT["validation"][f"[DB] {label}"] = "OK" if ok else "FAILED"
                print(f"  - check '{label}': {'OK' if ok else 'FAILED'}")
    finally:
        conn.close()


# =============================================================================
# main
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="ETL for the CVE Data Warehouse")
    ap.add_argument("--data-dir", default=".", help="folder with the CSV files")
    ap.add_argument("--dry-run", action="store_true", help="skip the database load")
    args = ap.parse_args()
    data_dir = Path(args.data_dir)

    rec, cwe, cpe, epss, kev, mitre = extract(data_dir)

    print("[2/5] Clean sources")
    rec = transform_records(rec)
    epss = transform_epss(epss)
    cwe_primary = transform_cwe(cwe)
    cnt, primary, affected = transform_cpe(cpe)
    kev = transform_kev(kev, cnt)

    print("[3/5] Build dimensions")
    dim_date = build_dim_date(rec["published_day"], kev["date_added_day"], kev["due_day"])
    dim_product = build_dim_product(primary, kev)
    dim_cwe = build_dim_cwe(pd.concat([cwe_primary["cwe_id"]]), mitre)
    dim_sev = build_dim_severity(rec)
    dim_exp = build_dim_exploit_type(rec)
    for n, d in (("dim_date", dim_date), ("dim_product", dim_product), ("dim_cwe", dim_cwe),
                 ("dim_severity", dim_sev), ("dim_exploit_type", dim_exp)):
        REPORT["dimensions"][n] = len(d)
        print(f"  - {n}: {len(d):,} rows")

    print("[4/5] Build facts")
    fact_v, fact_k = build_facts(rec, epss, cwe_primary, primary, affected, kev,
                                 dim_product, dim_cwe, dim_sev, dim_exp)
    print(f"  - fact_vulnerability: {len(fact_v):,} rows")
    print(f"  - fact_kev_addition:  {len(fact_k):,} rows")

    dim_exp_db = dim_exp.rename(columns={"f_rce": "has_rce", "f_xss": "has_xss",
                                         "f_sqli": "has_sql_injection",
                                         "f_bof": "has_buffer_overflow"})
    tables = {"dim_date": dim_date, "dim_product": dim_product, "dim_cwe": dim_cwe,
              "dim_severity": dim_sev, "dim_exploit_type": dim_exp_db,
              "fact_vulnerability": fact_v, "fact_kev_addition": fact_k}

    if args.dry_run:
        print("[5/5] Dry run: database not touched")
    else:
        load(tables)

    with open("etl_report.json", "w") as fh:
        json.dump(REPORT, fh, indent=2, default=str)
    print("Done. Report written to etl_report.json")


if __name__ == "__main__":
    main()
