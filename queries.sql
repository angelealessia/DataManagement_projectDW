-- QUERY 1: trend + severità
SELECT t.year, s.level AS severity, COUNT(*) AS cve_count
FROM fact_vulnerability f
JOIN dim_time t ON f.time_id = t.time_id
JOIN dim_severity s ON f.severity_id = s.severity_id
WHERE t.year BETWEEN 2020 AND 2026
  AND s.level IN ('CRITICAL','HIGH','MEDIUM','LOW')
GROUP BY t.year, s.level
ORDER BY t.year, s.level;

-- QUERY 2: matrice CVSS vs EPSS (NaN fix: exclude non-finite values)
SELECT cve_id, cvss_score, epss_score, epss_percentile,
    CASE
        WHEN cvss_score >= 9 AND epss_score <= 0.01 THEN 'Falso allarme'
        WHEN cvss_score <= 6 AND epss_score >= 0.5  THEN 'Pericolo nascosto'
        WHEN cvss_score >= 7 AND epss_score >= 0.5  THEN 'Rischio reale'
        ELSE 'Standard'
    END AS risk_category
FROM fact_vulnerability
WHERE cvss_score IS NOT NULL AND epss_score IS NOT NULL
  AND cvss_score::text NOT IN ('NaN','Infinity','-Infinity')
  AND epss_score::text NOT IN ('NaN','Infinity','-Infinity')
ORDER BY epss_score DESC LIMIT 20;

-- QUERY 3: time-to-exploit per vendor
SELECT v.vendor, COUNT(*) AS cve_count,
    ROUND(AVG(v.kev_date_added - t.published_date)) AS avg_days_to_exploit,
    MIN(v.kev_date_added - t.published_date) AS min_days,
    MAX(v.kev_date_added - t.published_date) AS max_days
FROM fact_vulnerability f
JOIN dim_vendor v ON f.vendor_id = v.vendor_id
JOIN dim_time t ON f.time_id = t.time_id
WHERE v.kev_date_added IS NOT NULL AND t.published_date IS NOT NULL
  AND (v.kev_date_added - t.published_date) >= 0
GROUP BY v.vendor HAVING COUNT(*) >= 3
ORDER BY avg_days_to_exploit ASC LIMIT 20;

-- QUERY 4: CWE frequenza vs sfruttamento
SELECT f.cwe_id, COUNT(*) AS total_cve,
    SUM(CASE WHEN f.is_known_exploited THEN 1 ELSE 0 END) AS exploited_count,
    ROUND(AVG(CASE WHEN f.epss_score::text NOT IN ('NaN','Infinity','-Infinity') THEN f.epss_score END)::numeric, 4) AS avg_epss,
    DENSE_RANK() OVER (ORDER BY COUNT(*) DESC) AS rank_by_frequency,
    DENSE_RANK() OVER (ORDER BY SUM(CASE WHEN f.is_known_exploited THEN 1 ELSE 0 END) DESC) AS rank_by_exploitation
FROM fact_vulnerability f
WHERE f.cwe_id IS NOT NULL
  AND f.cwe_id NOT IN ('NVD-CWE-noinfo','NVD-CWE-Other')
GROUP BY f.cwe_id ORDER BY exploited_count DESC LIMIT 20;

-- QUERY 5: top vendor per KEV
SELECT v.vendor, COUNT(*) AS total_kev,
    ROUND(AVG(CASE WHEN f.epss_score::text NOT IN ('NaN','Infinity','-Infinity') THEN f.epss_score END)::numeric, 4) AS avg_epss,
    ROUND(AVG(CASE WHEN f.cvss_score::text NOT IN ('NaN','Infinity','-Infinity') THEN f.cvss_score END)::numeric, 2) AS avg_cvss
FROM fact_vulnerability f
JOIN dim_vendor v ON f.vendor_id = v.vendor_id
WHERE v.vendor IS NOT NULL AND f.is_known_exploited = true
GROUP BY v.vendor HAVING COUNT(*) >= 2
ORDER BY total_kev DESC LIMIT 15;

-- QUERY 6: exploit type
SELECT
    CASE WHEN e.has_rce THEN 'RCE'
         WHEN e.has_sql_injection THEN 'SQL Injection'
         WHEN e.has_xss THEN 'XSS'
         WHEN e.has_buffer_overflow THEN 'Buffer Overflow'
         ELSE 'Other' END AS exploit_type,
    COUNT(*) AS cve_count,
    ROUND(AVG(CASE WHEN f.epss_score::text NOT IN ('NaN','Infinity','-Infinity') THEN f.epss_score END)::numeric, 4) AS avg_epss,
    ROUND(AVG(CASE WHEN f.cvss_score::text NOT IN ('NaN','Infinity','-Infinity') THEN f.cvss_score END)::numeric, 2) AS avg_cvss,
    SUM(CASE WHEN f.is_known_exploited THEN 1 ELSE 0 END) AS known_exploited
FROM fact_vulnerability f
JOIN dim_exploit_type e ON f.exploit_type_id = e.exploit_type_id
GROUP BY exploit_type ORDER BY avg_epss DESC;
