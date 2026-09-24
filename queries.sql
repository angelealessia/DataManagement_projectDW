-- =============================================================================
-- CVE Data Warehouse - OLAP queries
-- Data Management 2025/2026 - Alessia Angele (2003000)
--
-- Cubes
--   C1 fact_vulnerability  (published_date, product, cwe, severity, exploit_type)
--      measures: count, cvss_score, epss_score, epss_percentile, affected_products, is_in_kev
--   C2 fact_kev_addition   (date_added, due_date, published_date, product, cwe)
--      measures: count, days_to_kev, remediation_days, is_ransomware
--
-- Hierarchies
--   dim_date    : day -> month -> quarter -> year
--   dim_product : product -> vendor
--   dim_cwe     : cwe -> pillar            (MITRE CWE view 1000)
--
-- Conformed dimensions shared by C1 and C2: dim_date, dim_product, dim_cwe
-- Key -1 = "Unknown" member: excluded when the dimension is being analysed.
-- =============================================================================


-- =============================================================================
-- Q1  [ROLL-UP]  dim_date: quarter -> year  (+ grand total)
-- Cube C1 | Question: how is the number of published CVEs growing,
--                     and how is it split by severity?
-- ROLLUP produces the quarter rows, the year subtotals (quarter = NULL)
-- and the grand total (year = NULL) in a single pass.
-- =============================================================================
SELECT
    d.year,
    d.quarter,
    COUNT(*)                                                   AS cve_count,
    COUNT(*) FILTER (WHERE s.severity_level = 'CRITICAL')      AS critical,
    COUNT(*) FILTER (WHERE s.severity_level = 'HIGH')          AS high,
    COUNT(*) FILTER (WHERE s.severity_level = 'MEDIUM')        AS medium,
    COUNT(*) FILTER (WHERE s.severity_level = 'LOW')           AS low,
    ROUND(AVG(f.cvss_score), 2)                                AS avg_cvss
FROM fact_vulnerability f
JOIN dim_date     d ON d.date_key     = f.published_date_key
JOIN dim_severity s ON s.severity_key = f.severity_key
WHERE d.date_key <> -1
GROUP BY ROLLUP (d.year, d.quarter)
ORDER BY d.year NULLS LAST, d.quarter NULLS LAST;


-- =============================================================================
-- Q2a [ROLL-UP]  dim_cwe: cwe -> pillar
-- Cube C1 | Question: which families of weaknesses are most exploited?
-- exploitation_rate = share of CVEs of the family that ended up in CISA KEV.
-- NVD placeholders (NVD-CWE-noinfo/Other) and CWEs outside MITRE view 1000
-- have no pillar and are excluded.
-- =============================================================================
SELECT
    c.pillar_name,
    COUNT(*)                                                   AS cve_count,
    COUNT(*) FILTER (WHERE f.is_in_kev)                        AS in_kev,
    ROUND(100.0 * COUNT(*) FILTER (WHERE f.is_in_kev) / COUNT(*), 3) AS exploitation_rate_pct,
    ROUND(AVG(f.epss_score), 4)                                AS avg_epss
FROM fact_vulnerability f
JOIN dim_cwe c ON c.cwe_key = f.cwe_key
WHERE c.pillar_id IS NOT NULL
GROUP BY c.pillar_name
ORDER BY in_kev DESC;


-- =============================================================================
-- Q2b [DRILL-DOWN]  dim_cwe: pillar -> cwe
-- Cube C1 | Opens the most exploited pillar of Q2a into its individual CWEs.
-- Change the pillar name to drill into another family.
-- The two RANKs compare "most frequent" with "most exploited".
-- =============================================================================
SELECT
    c.cwe_id,
    c.cwe_name,
    COUNT(*)                                                   AS cve_count,
    COUNT(*) FILTER (WHERE f.is_in_kev)                        AS in_kev,
    ROUND(AVG(f.epss_score), 4)                                AS avg_epss,
    RANK() OVER (ORDER BY COUNT(*) DESC)                       AS rank_by_frequency,
    RANK() OVER (ORDER BY COUNT(*) FILTER (WHERE f.is_in_kev) DESC) AS rank_by_exploitation
FROM fact_vulnerability f
JOIN dim_cwe c ON c.cwe_key = f.cwe_key
WHERE c.pillar_name = (                 -- pillar with most KEV entries (from Q2a)
        SELECT c2.pillar_name
        FROM fact_vulnerability f2 JOIN dim_cwe c2 ON c2.cwe_key = f2.cwe_key
        WHERE f2.is_in_kev AND c2.cwe_key <> -1 AND c2.pillar_id IS NOT NULL
        GROUP BY c2.pillar_name ORDER BY COUNT(*) DESC LIMIT 1)
GROUP BY c.cwe_id, c.cwe_name
ORDER BY in_kev DESC, cve_count DESC
LIMIT 15;


-- =============================================================================
-- Q3  [SLICE]  dim_date.year = 2025
-- Cube C1 | Question: in 2025, which attack classes carry the highest risk?
-- One dimension fixed to a single value -> a 2-D sub-cube (exploit type x severity).
-- =============================================================================
SELECT
    e.primary_class                                            AS exploit_class,
    COUNT(*)                                                   AS cve_count,
    COUNT(*) FILTER (WHERE s.severity_level IN ('CRITICAL','HIGH')) AS critical_or_high,
    ROUND(AVG(f.cvss_score), 2)                                AS avg_cvss,
    ROUND(AVG(f.epss_score), 4)                                AS avg_epss,
    COUNT(*) FILTER (WHERE f.is_in_kev)                        AS in_kev
FROM fact_vulnerability f
JOIN dim_date         d ON d.date_key         = f.published_date_key
JOIN dim_exploit_type e ON e.exploit_type_key = f.exploit_type_key
JOIN dim_severity     s ON s.severity_key     = f.severity_key
WHERE d.year = 2025                                            -- the slice
GROUP BY e.primary_class
ORDER BY avg_epss DESC NULLS LAST;


-- =============================================================================
-- Q4  [DICE]  severity IN (CRITICAL, HIGH)  AND  attack_vector = NETWORK
--             AND year 2022-2025  AND  product_type = application
-- Cube C1 | Question: among remotely reachable, severe application flaws,
--                     which vendors accumulate the most real-world risk?
-- Several dimensions restricted at once -> a smaller sub-cube.
-- =============================================================================
SELECT
    p.vendor,
    COUNT(*)                                                   AS cve_count,
    COUNT(*) FILTER (WHERE f.is_in_kev)                        AS in_kev,
    ROUND(AVG(f.epss_score), 4)                                AS avg_epss,
    COUNT(*) FILTER (WHERE f.epss_percentile >= 0.95)          AS epss_top5pct
FROM fact_vulnerability f
JOIN dim_date     d ON d.date_key     = f.published_date_key
JOIN dim_severity s ON s.severity_key = f.severity_key
JOIN dim_product  p ON p.product_key  = f.product_key
WHERE s.severity_level IN ('CRITICAL', 'HIGH')
  AND s.attack_vector  = 'NETWORK'
  AND d.year BETWEEN 2022 AND 2025
  AND p.product_type   = 'application'
GROUP BY p.vendor
HAVING COUNT(*) >= 10
ORDER BY epss_top5pct DESC, in_kev DESC
LIMIT 15;


-- =============================================================================
-- Q5  [PIVOT]  CVSS band (rows) x EPSS band (columns)
-- Cube C1 | Question: does theoretical severity (CVSS) agree with
--                     predicted exploitation (EPSS)?
-- Rotates the EPSS dimension into columns: a 4x4 contingency matrix.
-- Top-right cell = "hidden danger" (low CVSS, high EPSS);
-- bottom-left   = "false alarm"   (critical CVSS, negligible EPSS).
-- =============================================================================
WITH banded AS (
    SELECT
        CASE WHEN cvss_score >= 9 THEN '4 Critical (9-10)'
             WHEN cvss_score >= 7 THEN '3 High (7-8.9)'
             WHEN cvss_score >= 4 THEN '2 Medium (4-6.9)'
             ELSE                      '1 Low (0-3.9)' END     AS cvss_band,
        epss_score
    FROM fact_vulnerability
    WHERE cvss_score IS NOT NULL AND epss_score IS NOT NULL
)
SELECT
    cvss_band,
    COUNT(*) FILTER (WHERE epss_score <  0.01)                       AS "EPSS <1%",
    COUNT(*) FILTER (WHERE epss_score >= 0.01 AND epss_score < 0.10) AS "EPSS 1-10%",
    COUNT(*) FILTER (WHERE epss_score >= 0.10 AND epss_score < 0.50) AS "EPSS 10-50%",
    COUNT(*) FILTER (WHERE epss_score >= 0.50)                       AS "EPSS >=50%",
    COUNT(*)                                                         AS total
FROM banded
GROUP BY cvss_band
ORDER BY cvss_band;


-- =============================================================================
-- Q6  [DRILL-ACROSS]  C1 fact_vulnerability  <->  C2 fact_kev_addition
-- Question: per vendor and year, how many CVEs are disclosed and how many
--           CVEs of that vendor are confirmed exploited in the same year?
-- Each fact is aggregated SEPARATELY to the common grain (vendor, year)
-- through the conformed dimensions dim_product and dim_date, then the two
-- result sets are joined. (Joining the facts directly would be wrong: it
-- would multiply rows.)
-- Note: C2 counts the year of addition to KEV, whatever the publication year,
-- so exploitation of older CVEs (before 2020) is also included.
-- The CISA KEV catalog was created in November 2021: 2020 is excluded (always 0)
-- and 2021-2022 contain the initial back-fill of already-known exploited CVEs.
-- =============================================================================
WITH published AS (                          -- cube C1 at grain (vendor, year)
    SELECT p.vendor, d.year, COUNT(*) AS cve_published
    FROM fact_vulnerability f
    JOIN dim_product p ON p.product_key = f.product_key
    JOIN dim_date    d ON d.date_key    = f.published_date_key
    WHERE p.product_key <> -1
    GROUP BY p.vendor, d.year
),
exploited AS (                               -- cube C2 at grain (vendor, year)
    SELECT p.vendor, d.year,
           COUNT(*)                                AS cve_added_to_kev,
           COUNT(*) FILTER (WHERE k.is_ransomware) AS ransomware_related
    FROM fact_kev_addition k
    JOIN dim_product p ON p.product_key = k.product_key
    JOIN dim_date    d ON d.date_key    = k.date_added_key
    WHERE p.product_key <> -1
    GROUP BY p.vendor, d.year
),
top_vendors AS (                             -- the 10 vendors most present in KEV
    SELECT vendor FROM exploited
    GROUP BY vendor ORDER BY SUM(cve_added_to_kev) DESC LIMIT 10
)
SELECT
    COALESCE(pu.vendor, ex.vendor)                            AS vendor,
    COALESCE(pu.year,   ex.year)                              AS year,
    COALESCE(pu.cve_published, 0)                             AS cve_published,
    COALESCE(ex.cve_added_to_kev, 0)                          AS cve_added_to_kev,
    COALESCE(ex.ransomware_related, 0)                        AS ransomware_related,
    ROUND(1000.0 * COALESCE(ex.cve_added_to_kev, 0)
          / NULLIF(pu.cve_published, 0), 1)                   AS kev_per_1000_published
FROM published pu
FULL OUTER JOIN exploited ex ON ex.vendor = pu.vendor AND ex.year = pu.year
WHERE COALESCE(pu.vendor, ex.vendor) IN (SELECT vendor FROM top_vendors)
  AND COALESCE(pu.year, ex.year) BETWEEN 2021 AND 2025
ORDER BY vendor, year;


-- =============================================================================
-- Q7  [ROLL-UP]  dim_product: product -> vendor   (cube C2)
-- Question: how fast are vulnerabilities of each vendor exploited after
--           disclosure, and how often are they used by ransomware?
-- days_to_kev = date added to KEV - NVD publication date.
-- Negative values = exploited as zero-day (in KEV before NVD publication):
-- counted separately and excluded from the averages.
-- =============================================================================
SELECT
    p.vendor,
    COUNT(*)                                                   AS kev_entries,
    COUNT(*) FILTER (WHERE k.days_to_kev < 0)                  AS zero_day,
    ROUND(AVG(k.days_to_kev) FILTER (WHERE k.days_to_kev >= 0))                  AS avg_days_to_kev,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY k.days_to_kev)
        FILTER (WHERE k.days_to_kev >= 0)                      AS median_days_to_kev,
    ROUND(100.0 * COUNT(*) FILTER (WHERE k.is_ransomware) / COUNT(*), 1)          AS ransomware_pct,
    ROUND(AVG(k.remediation_days))                             AS avg_remediation_days
FROM fact_kev_addition k
JOIN dim_product p ON p.product_key = k.product_key
WHERE k.in_nvd_snapshot                    -- days_to_kev needs the NVD publication date
GROUP BY p.vendor
HAVING COUNT(*) >= 5
ORDER BY median_days_to_kev ASC
LIMIT 15;