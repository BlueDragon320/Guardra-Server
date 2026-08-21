# Guardra Server — Dedicated API, Admin Portal & Crawler Engine

A production-ready containerized FastAPI server that powers the **Guardra Privacy Suite** and **Guardra Standalone Browser Extension**.

Provides real-time policy evaluation (DPDP Act 2023 / GDPR / CCPA), an authorized **Admin Portal** for rating overrides, an **Automated Policy Crawler & Re-scoring Engine**, statutory data deletion generation, zero-knowledge k-anonymity breach audits, and privacy hub telemetry.

---

## 🛡️ Admin Rating Portal & Crawler

Guardra Server includes a built-in single-page **Admin Portal** served at `/admin`.

### Key Features:
* **Site Management**: View, search, and filter all cataloged websites by Grade (`A+` to `F`) and compliance status.
* **Rating & Rubric Overrides**: Authorized admins can manually adjust composite grades, numerical scores (`0–100`), 6-pillar rubric weights, DPDP Grievance Officer details, and summaries.
* **Automated Crawler & Re-scoring**:
  * Single-click **"🔄 Auto-Rescore All Sites"** runs background web scraping across all tracked domains.
  * Detects policy revisions, re-evaluates 6-pillar NLP rubric metrics, and publishes updated scores instantly to connected extensions and client dashboards.
* **Add Website**: Enter any domain (e.g. `zerodha.com`) with instant live scraping.

### Accessing the Admin Portal:
1. Open in browser:
   ```text
   https://guardra-api.botvaibhav.dev/admin
   ```
   *(or `http://localhost:8756/admin`)*
2. Enter your secret admin key:
   * **Default Secret Key**: `guardra_admin_secret_2026` *(Configurable via `ADMIN_SECRET_KEY` in `.env`)*.

---

## 📜 Rating Methodology & Rubric Specification

For the complete technical specification of how ratings are calculated, see [**`RATING_METHODOLOGY.md`**](RATING_METHODOLOGY.md).

### Summary Formula:
\[
S_{\text{total}} = \sum_{i=1}^{6} (w_i \times S_i) - P_{\text{penalties}}
\]

| Pillar | Weight | Focus Area |
|---|---|---|
| **1. Third-Party Data Sharing** | **25%** | Ad networks, data brokers, commercial syndication |
| **2. Cookies & Tracker Density** | **20%** | Pixels, fingerprinters, analytics SDKs |
| **3. User Rights & Erasure Flow** | **20%** | Self-service deletion, Section 12 DPDP / GDPR Art 17 |
| **4. Data Retention Limits** | **15%** | Auto-purging limits vs indefinite retention |
| **5. Breach History & Safeguards**| **10%** | Technical encryption (AES-256, TLS 1.3) & past breaches |
| **6. Plain-Language Clarity** | **10%** | Flesch Reading Ease readability index |

---

## 🚀 Quickstart with Docker (Recommended)

### 1. Configure Environment
```bash
cd /home/blue/CIH/Guardra-Server
cp .env.example .env
```

### 2. Build & Run Container
```bash
docker compose up -d --build
```

### 3. Verify Server Status
```bash
curl http://localhost:8756/api/health
```

---

## 📡 API Reference

Interactive Swagger documentation is available at: `/docs`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/admin` | Admin Portal UI (SPA) |
| `POST` | `/api/admin/login` | Authenticates admin session |
| `GET` | `/api/admin/sites` | Lists all monitored sites (search & filter) |
| `PUT` | `/api/admin/sites/{domain}` | Overrides site rating, rubric, and DPDP contacts |
| `POST` | `/api/admin/sites` | Adds a new website with optional auto-scraping |
| `DELETE` | `/api/admin/sites/{domain}` | Deletes a site from the database |
| `POST` | `/api/admin/crawler/rescore-site` | Live scrapes and re-scores a single site |
| `POST` | `/api/admin/crawler/rescore-all` | Triggers bulk background policy crawler |
| `GET` | `/api/admin/crawler/status` | Polling endpoint for crawler progress |
| `GET` | `/api/policy/rating?domain=example.com` | Public policy scoring query |
| `POST` | `/api/deletion/generate-notice` | Generates DPDP Sec 12 statutory notice |
| `POST` | `/api/breach/check-password` | Zero-knowledge K-Anonymity password audit |

---

## 🛠️ Updating Container on Your VPS

When updating files on your production server:
```bash
cd ~/Guardra-Server
git pull
docker compose up -d --build
```
