# Guardra Server — Dedicated API & Scoring Engine

A production-ready containerized FastAPI server that powers the **Guardra Privacy Suite** and **Guardra Standalone Browser Extension**.

Provides real-time policy evaluation (DPDP Act 2023 / GDPR / CCPA), live web policy scraping, statutory data deletion request generation, zero-knowledge k-anonymity breach audits, and privacy hub telemetry.

---

## 🚀 Quickstart with Docker (Recommended)

### 1. Prerequisites
Ensure you have Docker and Docker Compose installed on your host server:
```bash
docker --version
docker compose version
```

---

### 2. Configure Environment
Clone or navigate to the server directory:
```bash
cd /home/blue/CIH/Guardra-Server
cp .env.example .env
```

*(Optional: Edit `.env` if you wish to change the exposed port or restrict CORS origins)*.

---

### 3. Build & Run Container
Launch the server in detached mode:
```bash
docker compose up -d --build
```

---

### 4. Verify Server Health
Check running container status:
```bash
docker compose ps
```

Test the health check endpoint:
```bash
curl http://localhost:8000/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Guardra Server Backend",
  "version": "1.0.0"
}
```

---

## 🌐 Production Domain & SSL Setup (HTTPS)

When deploying to a public VPS / cloud server (e.g. AWS EC2, DigitalOcean, Hetzner), set up a reverse proxy with SSL.

### Option A: Caddy (Simplest — Automatic Free SSL)
Create a `Caddyfile`:
```caddy
api.yourdomain.com {
    reverse_proxy localhost:8000
}
```
Run Caddy: `caddy run` (Caddy automatically provisions Let's Encrypt SSL certificates).

---

### Option B: Nginx + Certbot
Example Nginx server block (`/etc/nginx/sites-available/guardra`):
```nginx
server {
    server_name api.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Enable and provision SSL:
```bash
sudo ln -s /etc/nginx/sites-available/guardra /etc/nginx/sites-enabled/
sudo certbot --nginx -d api.yourdomain.com
```

---

## 🔌 Connecting the Standalone Extension

Once your server is live at `https://api.yourdomain.com`:

1. Click the **Guardra extension icon** in your browser.
2. Click **⚙️ Settings** (or open `chrome-extension://<id>/options/options.html`).
3. Set **API Server URL** to:
   ```text
   https://api.yourdomain.com
   ```
4. Click **Save**.

The standalone extension will now query your remote server for real-time live site scoring while falling back to its internal offline database whenever internet is unavailable.

---

## 📡 API Reference Overview

Interactive Swagger documentation is available at: `http://localhost:8000/docs`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health and active modules |
| `GET` | `/api/policy/rating?domain=example.com` | Evaluates site privacy against DPDP/GDPR rubric |
| `POST` | `/api/policy/analyze` | Scrapes and NLP-evaluates raw policy URL |
| `GET` | `/api/policy/cached` | Returns pre-scored platform database |
| `POST` | `/api/deletion/generate-notice` | Generates DPDP Sec 12 / GDPR Art 17 statutory notice |
| `POST` | `/api/deletion/generate-pdf` | Returns downloadable official PDF deletion letter |
| `POST` | `/api/breach/check-password` | Zero-knowledge K-Anonymity password audit |
| `POST` | `/api/breach/check-email` | Scans breach records for email exposure |
| `GET` | `/api/hub/platforms` | Platform privacy opt-out directory deep-links |
| `GET` | `/api/deletion/regulators` | Data protection authority directory (DPBI, CNIL, ICO) |

---

## 🛠️ Management Commands

* **View live logs**:
  ```bash
  docker compose logs -f guardra-api
  ```
* **Restart service**:
  ```bash
  docker compose restart
  ```
* **Stop service**:
  ```bash
  docker compose down
  ```
* **Update and rebuild**:
  ```bash
  docker compose up -d --build
  ```
