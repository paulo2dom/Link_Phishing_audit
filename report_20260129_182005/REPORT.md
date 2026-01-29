# 🔍 Email Link Forensic Analysis Report

<div align="center">

**Automated Phishing Detection & Forensic Evidence Collection**

</div>

---

📅 **Report Generated:** 2026-01-29 18:20:10 UTC

🛠️ **Tool:** analyze_email_links.sh v2.0.0

---

## 📊 Executive Summary

This report contains forensic evidence collected from **3** URLs extracted from email messages.

### Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| 🚨 **CRITICAL** (70-100) | 0 | 0% |
| 🔴 **HIGH** (50-69) | 0 | 0% |
| 🟠 **MEDIUM** (30-49) | 2 | 66% |
| 🟡 **LOW** (15-29) | 1 | 33% |
| 🟢 **MINIMAL** (0-14) | 0 | 0% |

**Average Risk Score:** 28/100


### Analysis Scope

| Feature | Status |
|---------|--------|
| HTTP/HTTPS Collection | ✅ Enabled |
| DNS Resolution | ✅ Enabled |
| TLS Inspection | ✅ Enabled |
| Content Analysis | ✅ Enabled |
| Typosquatting Detection | ✅ Enabled |
| Brand Impersonation | ✅ Enabled |
| Obfuscation Detection | ✅ Enabled |
| Risk Scoring | ✅ Enabled |

### Security Configuration

- **Max Response Size:** 200KB
- **Connection Timeout:** 20s
- **Max Redirects:** 5
- **JavaScript Execution:** ❌ Disabled (Safe)
- **Form Submission:** ❌ Disabled (Safe)

---

## 🎯 URL Analysis Results

### Summary Table

| # | Risk | URL | Status | Server | Redirects | Key Findings |
|---|------|-----|--------|--------|-----------|--------------|
| 1 | 🟠 36 | `https://google.com` | 200 | gws | 1 | 🏢 ⏰  |
| 2 | 🟡 18 | `https://login.microsoftonline.com` | 200 | N/A | 0 | 🏢 ⏰ 🎭  |
| 3 | 🟠 30 | `https://www.microsoft.com` | 200 | AkamaiNetStorag | 0 | 🏢 ⏰  |

**Legend:** 🔑=Password Field 🏢=Brand Mention ⏰=Urgency Language 🎭=Typosquatting 🌐=Suspicious TLD

---

## 📋 Detailed URL Analysis

### [1] 🟠 MEDIUM - Risk Score: 36/100

**Original URL:** `https://google.com`

**Final URL (after redirects):** `https://www.google.com/`

| Property | Value |
|----------|-------|
| Domain | `google.com` |
| Status Code | 200 |
| Server | gws |
| IP Addresses | 172.217.20.238  |
| Redirects | 1 |

<details>
<summary>🔎 URL & Security Analysis</summary>

```
URL Structure Risk Factors: 0
⚠️  Possible homograph attack detected
✓ HSTS header present
✓ CSP header present
✓ X-Frame-Options present
⚠️  Missing: X-Content-Type-Options
✓ X-XSS-Protection present
Security Headers Score: 4/5
## Certificate Risk Analysis
ℹ️  Wildcard certificate detected
✓ Certificate verification: OK
Certificate Risk Score: 0
```
</details>

<details>
<summary>📄 Content Analysis</summary>

```
  🏢 Google mentioned: 24 times
  🏢 Gmail mentioned: 1 times
  ⚠️  'expire': 1
URGENCY_SCORE=1
Forms found: 1
🚨 Credit card related fields: 1
🚨 SSN/Tax ID related fields: 1
⚠️  Base64 operations: 4
⚠️  Meta refresh redirects: 1
⚠️  JavaScript redirects: 4
⚠️  Data transmission methods: 4
## Script Analysis
Script tags: 5
Password Fields: 0
CONTENT_RISK_SCORE=17
```
</details>

<details>
<summary>📊 Risk Score Breakdown</summary>



| Category | Raw Score | Weighted |
|----------|-----------|----------|
| Content Analysis | 17 | 34/40 |
| URL Structure | 0 | 0/20 |
| Certificate | 0 | 0/15 |
| Security Headers | 2 | 2/10 |
| Redirects | 0 | 0/15 |


Risk Level: 🟠 MEDIUM

RISK_SCORE=36
RISK_LEVEL=MEDIUM
</details>

---

### [2] 🟡 LOW - Risk Score: 18/100

**Original URL:** `https://login.microsoftonline.com`

**Final URL (after redirects):** `https://login.microsoftonline.com/`

| Property | Value |
|----------|-------|
| Domain | `login.microsoftonline.com` |
| Status Code | 200 |
| Server | N/A |
| IP Addresses | 20.190.177.21 20.190.147.7 20.190.147.4  |
| Redirects | 0 |

<details>
<summary>🔎 URL & Security Analysis</summary>

```
URL Structure Risk Factors: 0
⚠️  Contains brand name 'microsoft' in domain: login.microsoftonline.com
⚠️  Possible homograph attack detected
✓ HSTS header present
✓ CSP header present
✓ X-Frame-Options present
✓ X-Content-Type-Options present
✓ X-XSS-Protection present
Security Headers Score: 5/5
## Certificate Risk Analysis
✓ Certificate verification: OK
Certificate Risk Score: 0
```
</details>

<details>
<summary>📄 Content Analysis</summary>

```
  🏢 Microsoft mentioned: 2 times
  ⚠️  'expire': 1
URGENCY_SCORE=1
Forms found: 0
🚨 Credit card related fields: 1
✓ No significant obfuscation detected
⚠️  JavaScript redirects: 3
⚠️  Data transmission methods: 1
## Script Analysis
Script tags: 5
Password Fields: 0
CONTENT_RISK_SCORE=9
```
</details>

<details>
<summary>📊 Risk Score Breakdown</summary>



| Category | Raw Score | Weighted |
|----------|-----------|----------|
| Content Analysis | 9 | 18/40 |
| URL Structure | 0 | 0/20 |
| Certificate | 0 | 0/15 |
| Security Headers | 0 | 0/10 |
| Redirects | 0 | 0/15 |


Risk Level: 🟡 LOW

RISK_SCORE=18
RISK_LEVEL=LOW
</details>

---

### [3] 🟠 MEDIUM - Risk Score: 30/100

**Original URL:** `https://www.microsoft.com`

**Final URL (after redirects):** `https://www.microsoft.com/`

| Property | Value |
|----------|-------|
| Domain | `www.microsoft.com` |
| Status Code | 200 |
| Server | AkamaiNetStorage |
| IP Addresses | 72.247.166.29  |
| Redirects | 0 |

<details>
<summary>🔎 URL & Security Analysis</summary>

```
URL Structure Risk Factors: 0
⚠️  Possible homograph attack detected
⚠️  Missing: Strict-Transport-Security (HSTS)
⚠️  Missing: Content-Security-Policy
⚠️  Missing: X-Frame-Options
⚠️  Missing: X-Content-Type-Options
Security Headers Score: 0/5
## Certificate Risk Analysis
✓ Certificate verification: OK
Certificate Risk Score: 0
```
</details>

<details>
<summary>📄 Content Analysis</summary>

```
  🏢 Microsoft mentioned: 183 times
  🏢 Outlook mentioned: 3 times
  🏢 OneDrive mentioned: 3 times
  🏢 Teams mentioned: 10 times
  ⚠️  'locked': 1
URGENCY_SCORE=1
Forms found: 1
🚨 Credit card related fields: 2
✓ No significant obfuscation detected
## Script Analysis
Script tags: 5
Password Fields: 0
CONTENT_RISK_SCORE=11
```
</details>

<details>
<summary>📊 Risk Score Breakdown</summary>



| Category | Raw Score | Weighted |
|----------|-----------|----------|
| Content Analysis | 11 | 22/40 |
| URL Structure | 0 | 0/20 |
| Certificate | 0 | 0/15 |
| Security Headers | 8 | 8/10 |
| Redirects | 0 | 0/15 |


Risk Level: 🟠 MEDIUM

RISK_SCORE=30
RISK_LEVEL=MEDIUM
</details>

---

## 🎯 Indicators of Compromise (IOCs)

> Copy these IOCs for threat intelligence feeds, SIEM rules, or blocklists.

### Domains

```
google.com
login.microsoftonline.com
www.microsoft.com
```

### IP Addresses

```
172.217.20.238
20.190.147.12
20.190.147.4
20.190.147.5
20.190.147.6
20.190.147.7
20.190.147.8
20.190.177.21
20.190.177.23
72.247.166.29
```

### Final URLs (Post-Redirect)

```
https://login.microsoftonline.com/
https://www.google.com/
https://www.microsoft.com/
```

### TLS Certificate SHA256 Fingerprints

```

```

### High-Risk URLs (Score ≥ 50)

```
```

---

## 📁 Evidence Files Structure

```
./report_20260129_182005/
├── 📄 REPORT.md (this file)
├── 📄 urls_normalized.txt (deduplicated input)
├── 📁 per_url/
│   └── <url_directory>/
│       ├── 📁 raw/
│       │   ├── headers.txt (HTTP headers)
│       │   ├── body.html (response body)
│       │   └── *.stderr (error logs)
│       ├── 📁 dns/
│       │   └── resolution.txt (A, AAAA, CNAME)
│       ├── 📁 tls/
│       │   ├── certificate.txt (cert details)
│       │   └── certificate_chain.pem
│       ├── 📁 analysis/
│       │   ├── content_analysis.txt
│       │   ├── url_analysis.txt
│       │   └── risk_score.txt
│       ├── metadata.env
│       └── hashes.txt
├── 📁 logs/
└── 📄 sha256sum_all.txt (chain of custody)
```

---

## 📖 Methodology

### Collection Techniques

| Method | Tool | Purpose |
|--------|------|---------|
| HTTP(S) | `curl` | Header & body collection |
| DNS | `dig`/`host` | A, AAAA, CNAME resolution |
| TLS | `openssl` | Certificate inspection |
| Hashing | `sha256sum` | Evidence integrity |

### Analysis Techniques

| Analysis | Description |
|----------|-------------|
| **Typosquatting** | Levenshtein distance against known brands |
| **Brand Impersonation** | Keyword matching for 20+ major brands |
| **Urgency Language** | Detection of fear/urgency tactics |
| **Credential Harvesting** | Password/CC/SSN field detection |
| **Obfuscation** | Base64, eval(), hex encoding detection |
| **URL Structure** | TLD, subdomain, encoding analysis |
| **Certificate Risk** | Self-signed, expired, free CA detection |
| **Security Headers** | HSTS, CSP, X-Frame-Options audit |

### Limitations

- ❌ No JavaScript execution (dynamic content not captured)
- ❌ No form submissions or POST requests
- ❌ No browser fingerprinting simulation
- ⚠️ DNS/TLS may fail due to network restrictions
- ⚠️ Sophisticated phishing may evade static analysis

---

## 🛡️ Recommendations

### Immediate Actions

1. **Block** all CRITICAL and HIGH risk URLs at the firewall/proxy
2. **Alert** users who may have received emails containing these URLs
3. **Report** confirmed phishing to the impersonated brand
4. **Submit** malicious URLs to threat intelligence feeds

### Investigation Steps

1. Review detailed analysis for each flagged URL
2. Cross-reference IOCs with your SIEM/threat intel
3. Check if any users clicked on the URLs (proxy logs)
4. Consider sandboxed browser analysis for suspicious pages

### Prevention

1. Implement email URL rewriting/sandboxing
2. Deploy browser isolation for untrusted links
3. Enable DMARC, SPF, DKIM for your domains
4. Conduct user awareness training on phishing

---

**Report End**

*Generated by analyze_email_links.sh v2.0.0*
