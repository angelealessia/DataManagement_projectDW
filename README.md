# NVD CVE CVSS KEV EPSS Vulnerabilities 2020-2026

## Start Here

Companion notebook: https://www.kaggle.com/code/afr1ste/nvd-cve-cvss-kev-vulnerability-map

- Official NVD CVE JSON 2.0 feed snapshot from 2020-2026, joined to the CISA Known Exploited Vulnerabilities catalog and FIRST EPSS current scores.
- Includes CVSS v4.0/v3.1/v3.0/v2.0 metrics, CWE weakness IDs, CPE vendor/product matches, references, exploit text flags, KEV labels, and EPSS probability/percentile fields.
- Good first tasks: vulnerability priority ranking, CVSS-vs-EPSS comparison, known-exploited vulnerability screening, CWE/CPE trend analysis, vendor/product risk summaries, and vulnerability management dashboards.

Caveat: KEV labels are positive known-exploited entries from CISA, not a complete negative label for all non-KEV CVEs. EPSS is a probabilistic current score, not a guarantee of exploitation.

## Snapshot

- Build date: 2026-05-02T09:53:36Z
- Years: 2020-2026
- CVEs: 201542
- CPE match rows: 1550739
- CWE weakness rows: 260862
- Reference rows: 708018
- CISA KEV rows: 1585
- FIRST EPSS current rows: 329934
- CVEs in this date range that are in CISA KEV: 1039
- CVEs with preferred CVSS score: 192568
- CVEs with EPSS score: 194478
- EPSS score date: 2026-05-01T12:55:00Z

## Files

- `nvd_cve_records.csv`: main CVE-level table.
- `nvd_cve_records.parquet`: Parquet version of the main table.
- `nvd_cve_cpe_matches.csv`: CPE criteria rows.
- `nvd_cve_weaknesses.csv`: CWE rows.
- `nvd_cve_references.csv`: reference URL rows.
- `cisa_kev_catalog.csv`: CISA KEV catalog snapshot.
- `first_epss_current.csv`: FIRST EPSS current score snapshot.
- `yearly_summary.csv`, `severity_summary.csv`, `cwe_summary.csv`, `vendor_product_summary.csv`, `kev_year_summary.csv`, `epss_summary.csv`: summary tables.
- `data_dictionary.csv`: table and column descriptions.
- `source_manifest.json`: source URLs and feed timestamps.
- `validation_summary.json`: validation counters.
- `citation_and_license.md`: provenance and caveats.
