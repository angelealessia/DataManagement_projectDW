# CVE Data Warehouse

OLAP analysis of software vulnerabilities published 2020–2026.
Data Management project, Sapienza University of Rome – Alessia Angele (2003000).

The warehouse integrates four public sources to compare what is **disclosed**
(NIST NVD), what is **predicted to be exploited** (FIRST EPSS) and what is
**confirmed exploited** (CISA KEV), across time, vendors and weakness types.

## Architecture

Two business processes are modelled as two fact tables that share conformed
dimensions (a fact constellation), implemented in PostgreSQL 16.

| Fact table | Grain | Measures |
|---|---|---|
| `fact_vulnerability` | one CVE published in NVD | `cvss_score`, `epss_score`, `epss_percentile`, `affected_products`, `is_in_kev` |
| `fact_kev_addition` | one CVE added to the CISA KEV catalog | `days_to_kev`, `remediation_days`, `is_ransomware` |

| Dimension | Hierarchy | Shared by both facts |
|---|---|---|
| `dim_date` | day → month → quarter → year | yes (3 roles in `fact_kev_addition`: added, due, published) |
| `dim_product` | product → vendor | yes |
| `dim_cwe` | cwe → pillar (MITRE CWE view 1000) | yes |
| `dim_severity` | severity, attack vector, attack complexity | no |
| `dim_exploit_type` | attack-class flags → primary class | no |

Every dimension has an `Unknown` member (key `-1`), so fact rows never have
NULL foreign keys.

## Repository

| File | Content |
|---|---|
| `etl.py` | ETL pipeline: extracts the source files, cleans and integrates them, builds and loads the warehouse, writes `etl_report.json` |
| `queries.sql` | 8 OLAP queries, each labelled with its operator |
| `export_results.py` | runs every query in `queries.sql` and saves the results to `results/` |
| `etl_report.json` | counts of everything the ETL cleaned, dropped, reconciled and validated |
| `results/` | query results as CSV (used for the charts in the presentation) |
| `docs/` | presentation (`project_presentation.pdf`) |

## How to run

**Requirements:** Python 3.10+, PostgreSQL 16.

```bash
pip install pandas numpy psycopg2-binary
createdb vulnerabilities_dw
```

**1. Download the data into `data/`** (not versioned: the files are up to 250 MB).

- Kaggle dataset [`afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026`](https://www.kaggle.com/datasets/afr1ste/nvd-cve-cvss-kev-vulnerabilities-2020-2026)
  (snapshot of 2 May 2026). Needed files: `nvd_cve_records.csv`,
  `nvd_cve_weaknesses.csv`, `nvd_cve_cpe_matches.csv`, `first_epss_current.csv`,
  `cisa_kev_catalog.csv`.
- MITRE CWE catalog, view 1000: <https://cwe.mitre.org/data/csv/1000.csv.zip>.
  Unzip it and rename the file to `cwe_1000.csv` (optional: without it the
  cwe → pillar hierarchy stays empty).

**2. Build the warehouse** (drops and recreates all tables, so it can be re-run):

```bash
python etl.py --data-dir data --dry-run   # transformations only, database untouched
python etl.py --data-dir data
```

The database connection is set in `DB_PARAMS` at the top of `etl.py` and
`export_results.py`.

**3. Run the queries**

```bash
python export_results.py        # results/Q1.csv ... results/Q7.csv
psql -d vulnerabilities_dw -f queries.sql
```

## ETL

The Kaggle dataset also contains a table where the author has already joined
NVD, EPSS and KEV. **It is not used as input.** The joins are done in
`etl.py`, starting from each provider's own file, and the pre-joined columns
are used only to check the result.

| Step | What it does |
|---|---|
| Extract | reads only the needed columns; stops with a clear message if a column is missing |
| Clean | validates CVE ids and removes duplicates; truncates timestamps to the day; turns empty, `NaN` and ±Infinity values into NULL, with range checks (CVSS 0–10, EPSS 0–1) |
| Integrate | joins the sources on the CVE id; keeps the NVD *Primary* CWE; parses CPE 2.3 strings to get vendor and product, keeping only vulnerable matches; reconciles CISA vendor names with NVD names (e.g. `d_link → dlink`, `android → google`) by majority vote over shared CVEs; takes CWE names and the cwe → pillar hierarchy from MITRE; computes the attack-class flags (RCE, XSS, SQL injection, buffer overflow) by keyword matching on the NVD description |
| Build | assigns surrogate keys and adds the `Unknown` member to each dimension; `dim_date` is a full calendar with key `YYYYMMDD` |
| Load & check | adds primary keys, foreign keys, unique constraints and indexes, then runs checks in SQL (dimension grain, KEV consistency between the two facts, no NaN) |

**Validation on the real data:** the joins find 194,478 CVEs with an EPSS
score and 1,039 CVEs in KEV. Both numbers match the reference exactly, with
0 disagreements.

### Data-quality findings

- **The Kaggle `mentions_*` flags leak the KEV label.** 1,036 of the 1,039 KEV
  CVEs are tagged as RCE and none as SQL injection or XSS. For this reason the
  attack classes are recomputed by keyword matching on the NVD description
  only. With the recomputed flags, the KEV CVEs are 362 RCE, 34 buffer
  overflow, 20 XSS and 18 SQL injection.
- 40,398 CVEs (20%) have no CPE match, so their product is `Unknown`.
- 546 KEV entries are CVEs published before 2020. They are kept in
  `fact_kev_addition` with `in_nvd_snapshot = false`.
- 61 CVEs were added to KEV before they were published in NVD (zero-days).

## OLAP queries

| Query | Operator | Question |
|---|---|---|
| Q1 | Roll-Up (quarter → year) | growth of published CVEs by severity |
| Q2a | Roll-Up (cwe → pillar) | which weakness families are exploited most |
| Q2b | Drill-Down (pillar → cwe) | most frequent vs most exploited CWEs in the top family |
| Q3 | Slice (year = 2025) | attack classes by severity and EPSS |
| Q4 | Dice (severity, vector, years, product type) | riskiest vendors for severe remote flaws |
| Q5 | Pivot (CVSS × EPSS) | does CVSS severity agree with predicted exploitation? |
| Q6 | Drill-Across (both facts) | CVEs published vs added to KEV, per vendor and year |
| Q7 | Roll-Up on the KEV cube (product → vendor) | how fast vulnerabilities are exploited |

## Main findings

- **Severity is not risk:** 68% of CVSS-critical CVEs have EPSS below 1%, while 337 "medium" CVEs have EPSS of 50% or more (Q5).
- **Frequency does not predict exploitation:** type confusion (CWE-843) is only 29th by volume but 5th by exploitation (Q2b).
- **Vendors differ in kind:** since 2023 Microsoft has about 30 KEV entries per 1,000 published CVEs, Ivanti over 60 (Q6); Fortinet flaws reach KEV in a median of 1 day (Q7).

## Limitations

- EPSS is a single current snapshot, not a history over time.
- KEV lists confirmed exploitation only: absence from KEV does not mean "not exploited".
- Attack classes come from keyword matching, which is a heuristic.
- The CISA KEV catalog starts in November 2021, and its first months include
  the back-fill of vulnerabilities that were already known to be exploited.

## Sources

- NIST National Vulnerability Database – <https://nvd.nist.gov>
- FIRST Exploit Prediction Scoring System – <https://www.first.org/epss>
- CISA Known Exploited Vulnerabilities Catalog – <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- MITRE Common Weakness Enumeration – <https://cwe.mitre.org>
- Snapshot of these sources prepared by Kaggle user `afr1ste` (see the dataset page for its licence and provenance).