# Guardra Privacy Scoring Methodology & Evaluation Rubric Specification

**Version:** 1.0.0  
**Frameworks Covered:** Digital Personal Data Protection Act 2023 (India), General Data Protection Regulation (EU GDPR), California Consumer Privacy Act (CCPA/CPRA).

---

## 1. Executive Summary

The **Guardra Privacy Scoring Engine** evaluates website privacy policies and telemetry architectures across a standardized **6-Pillar Composite Rubric**. 

The engine uses natural language processing (NLP), statutory keyword extractors, readability metrics, and client-side DOM telemetry analysis to compute a numerical score (\(0 - 100\)) and a letter grade (\(A+\) to \(F\)).

---

## 2. Mathematical Scoring Formula

The overall privacy score \(S_{\text{total}}\) is calculated as a weighted sum of the 6 individual pillar scores:

\[
S_{\text{total}} = \sum_{i=1}^{6} (w_i \times S_i) - P_{\text{penalties}}
\]

Where \(w_i\) represents the pillar weight and \(S_i \in [0, 100]\) represents the score of each pillar:

| Pillar ID | Assessment Area | Weight (\(w_i\)) | Max Points | Risk Focus |
|---|---|---|---|---|
| **P1** | **Third-Party Data Sharing & Commercial Syndication** | **25%** (0.25) | 25 | Ad networks, data brokers, partner sharing |
| **P2** | **Cookies, Tracking Pixels & Telemetry Density** | **20%** (0.20) | 20 | Canvas fingerprinters, analytics pixels, SDKs |
| **P3** | **User Rights & Statutory Erasure Flow** | **20%** (0.20) | 20 | Self-service deletion vs legal friction |
| **P4** | **Data Retention Limits & Auto-Purging** | **15%** (0.15) | 15 | Indefinite retention vs disclosed purge limits |
| **P5** | **Breach History, Security & Encryption** | **10%** (0.10) | 10 | Encryption at rest/transit, past security incidents |
| **P6** | **Plain-Language Clarity (Readability Index)** | **10%** (0.10) | 10 | Flesch Reading Ease & obfuscation penalties |

---

## 3. Detailed Pillar Evaluation Rubrics

---

### Pillar 1: Third-Party Data Sharing & Syndication (Weight: 25%)
Evaluates whether user data (identifiers, browsing intent, purchase history, geolocation) is sold, shared, or syndicated to external parties.

* **Score: 85 – 100 (Low Risk)**:
  * Policy explicitly states data is **never sold** or shared with third-party advertisers.
  * Vendor sharing is strictly limited to essential service infrastructure (e.g. payment processors, CDN).
* **Score: 50 – 84 (Moderate Risk)**:
  * Shares with affiliates, analytics vendors, and logistics partners under standard commercial agreements.
* **Score: 0 – 49 (High Risk)**:
  * Policy includes broad clauses permitting sharing with "commercial partners", "ad networks", "market research firms", or data brokers for cross-context behavioral advertising.

---

### Pillar 2: Cookies & Telemetry Density (Weight: 20%)
Evaluates the volume and invasiveness of active tracking technologies.

* **Score: 85 – 100 (Low Risk)**:
  * 0 to 1 first-party functional session cookies. Zero third-party tracking pixels (no Meta Pixel, no Google Tag Manager ad feeds).
* **Score: 55 – 84 (Moderate Risk)**:
  * Standard first-party analytics (e.g. Plausible, self-hosted Matomo, basic Google Analytics).
* **Score: 0 – 54 (High Risk)**:
  * Heavy tracker density: 4+ third-party ad networks detected (Meta Pixel, Criteo, TikTok Pixel, Taboola/Outbrain, AppsFlyer) and cross-device fingerprinters.

---

### Pillar 3: User Rights & Erasure Flow (Weight: 20%)
Evaluates how easily a user can exercise statutory data erasure and consent withdrawal.

* **Score: 85 – 100 (Low Risk)**:
  * Direct 1-click self-service account and data deletion in user profile settings.
  * Disclosed statutory compliance with India DPDP Act 2023 (Section 12) and GDPR Article 17.
* **Score: 55 – 84 (Moderate Risk)**:
  * Deletion available by emailing a designated Grievance Officer or Support desk within 30 days.
* **Score: 0 – 54 (High Risk)**:
  * Opaque deletion flow: Requires physical written letters, phone calls, or contains clauses claiming data "cannot be deleted from backups".

---

### Pillar 4: Data Retention Limits (Weight: 15%)
Evaluates how long personal data is retained by the Data Fiduciary.

* **Score: 85 – 100 (Low Risk)**:
  * Explicit retention schedules disclosed (e.g. "Server logs purged after 30 days; account data erased within 7 days of deletion request").
* **Score: 50 – 84 (Moderate Risk)**:
  * Data retained for defined legal and tax compliance periods (e.g. 5 to 7 years for financial records).
* **Score: 0 – 49 (High Risk)**:
  * Indefinite retention clauses: "We retain your information for as long as necessary to provide our services and for our legitimate business purposes."

---

### Pillar 5: Breach History & Security Safeguards (Weight: 10%)
Evaluates historical data breaches and disclosed technical safeguards.

* **Score: 85 – 100 (Low Risk)**:
  * Zero known public data leaks. End-to-end or zero-access encryption; TLS 1.3 in transit and AES-256 at rest.
* **Score: 60 – 84 (Moderate Risk)**:
  * Standard industry security architecture. No uncontained major leaks in past 3 years.
* **Score: 0 – 59 (High Risk)**:
  * Documented history of major data breaches (e.g. unencrypted plain text passwords, API credential leaks, scraped user databases).

---

### Pillar 6: Plain-Language Clarity & Readability (Weight: 10%)
Evaluates whether an average consumer can comprehend the policy without legal training.

Calculated using the **Flesch Reading Ease Formula**:
\[
\text{FRE} = 206.835 - 1.015 \left( \frac{\text{Total Words}}{\text{Total Sentences}} \right) - 84.6 \left( \frac{\text{Total Syllables}}{\text{Total Words}} \right)
\]

* **FRE > 65 (Score: 85–100)**: Plain language, short sentences, interactive summary tables.
* **FRE 40–65 (Score: 50–84)**: Standard commercial legal draft with structured headings.
* **FRE < 40 (Score: 10–49)**: Dense legal obfuscation designed to deter consumer scrutiny.

---

## 4. Grade Classification Bands

| Grade | Numerical Range | Color Code | Privacy Verdict |
|---|---|---|---|
| **A+** | **95 – 100** | Emerald (`#10b981`) | **Gold Standard Privacy**: Zero data sales, no tracking pixels, full statutory compliance. |
| **A** | **85 – 94** | Emerald (`#10b981`) | **High Privacy**: Minimal telemetry, explicit retention limits, 1-click erasure. |
| **B+ / B** | **70 – 84** | Green (`#22c55e`) | **Good Protection**: Standard functional sharing, verified DPDP/GDPR contacts. |
| **C+ / C** | **50 – 69** | Amber (`#f59e0b`) | **Moderate Risk**: Commercial ad retargeting, vendor sharing, standard 30-day deletion. |
| **D+ / D** | **35 – 49** | Orange (`#f97316`) | **High Exposure**: Deep behavioral profiling, ad network syndication, indefinite retention. |
| **F** | **0 – 34** | Red (`#ef4444`) | **Critical Risk**: Systematic shadow profiling, tracker density > 5, major breach history. |

---

## 5. Statutory Compliance Check Rules

### India DPDP Act 2023 Verification Checklist:
1. **Section 6(4)**: Right to withdraw consent with the same ease with which it was provided.
2. **Section 12**: Disclosed mechanism for erasure and correction of personal data.
3. **Section 13**: Identified in-house **Grievance Redressal Officer** with official name and email.
4. **SLA Window**: 30-day statutory resolution timeline before escalation to the Data Protection Board of India (DPBI).

### GDPR (EU) Verification Checklist:
1. **Article 6**: Lawful basis for processing clearly stated (Consent, Contract, Legitimate Interest).
2. **Article 17**: Right to Erasure ("Right to be Forgotten") disclosed.
3. **Article 37**: Dedicated Data Protection Officer (DPO) contact provided.

### CCPA / CPRA (California) Verification Checklist:
1. **Section 1798.120**: "Do Not Sell or Share My Personal Information" link provided.
2. **Section 1798.105**: Consumer right to request deletion of personal information.

---

## 6. Audit Workflow & Automation Lifecycle

```
[Live Policy URL / Domain]
         │
         ▼
[1. Content Scraper & Text Normalizer]
         │
         ▼
[2. Regex Statutory Parser (DPDP/GDPR/CCPA Contacts)]
         │
         ▼
[3. NLP Clause Classifier & Readability Analyzer]
         │
         ▼
[4. DOM Tracker & Consent Banner Inspection]
         │
         ▼
[5. Weighted Rubric Math Engine]
         │
         ▼
[Final Grade (A+ to F), Score (0-100), & Legal Notice Metadata]
```
