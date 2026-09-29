# SecureMailScope — Production Deployment Guide

> **Target environment:** Ubuntu/Debian VPS with Docker, nginx, and a Let's Encrypt certificate  
> **Domain:** `mailscope.dpdns.org` (frontend) · `api.mailscope.dpdns.org` (backend API)

---

## 1. Prerequisites

| Tool | Minimum version |
|------|----------------|
| Docker | 24+ |
| Docker Compose | v2.20+ |
| nginx | 1.24+ |
| Certbot | 2.x |
| Node.js | 20 LTS (for building frontend) |

---

## 2. Clone & Configure

```bash
git clone git@github.com:Amin-Patel/SecureMailScope.git /opt/mailscope
cd /opt/mailscope
```

### Backend secrets

```bash
cp backend/.env.example backend/.env
nano backend/.env          # Fill in real values (see section below)
```

Required variables in `backend/.env`:

| Variable | Where to find it |
|----------|-----------------|
| `SUPABASE_URL` | Supabase → Project Settings → API |
| `SUPABASE_PROJECT_REF` | Supabase project reference (part of the URL) |
| `SUPABASE_JWT_SECRET` | Supabase → Project Settings → API → JWT Settings |
| `ALLOWED_ORIGINS` | `https://mailscope.dpdns.org` (no trailing slash) |
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com) |

### Frontend production env

```bash
cp frontend/.env.example frontend/.env.production
nano frontend/.env.production   # Confirm VITE_API_BASE_URL and Supabase keys
```

---

## 3. Build the Frontend

```bash
cd frontend
npm ci
npm run build          # Produces frontend/dist/
cd ..
```

Copy the built assets to the nginx web root:

```bash
sudo mkdir -p /var/www/mailscope
sudo cp -r frontend/dist /var/www/mailscope/dist
sudo chown -R www-data:www-data /var/www/mailscope
```

---

## 4. Issue TLS Certificates

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Issue cert for both subdomains at once
sudo certbot certonly --nginx \
  -d mailscope.dpdns.org \
  -d api.mailscope.dpdns.org
```

Update the certificate paths in `nginx.conf` to match where Certbot writes them (usually `/etc/letsencrypt/live/mailscope.dpdns.org/fullchain.pem`).

---

## 5. Configure nginx

```bash
sudo cp nginx.conf /etc/nginx/sites-available/mailscope
sudo ln -s /etc/nginx/sites-available/mailscope /etc/nginx/sites-enabled/

# Test
sudo nginx -t

# Reload
sudo systemctl reload nginx
```

---

## 6. Start the Backend

```bash
# From project root
docker compose up -d --build

# Verify
docker compose logs -f backend
curl https://api.mailscope.dpdns.org/api/health
```

---

## 7. Supabase: Update Redirect URLs

In Supabase → **Authentication → URL Configuration**:

- **Site URL:** `https://mailscope.dpdns.org`
- **Additional Redirect URLs:**
  - `https://mailscope.dpdns.org/auth/callback`
  - `https://mailscope.dpdns.org/**`

---

## 8. DNS Records

Add the following to your `dpdns.org` DNS panel:

| Type | Name | Value |
|------|------|-------|
| A | `mailscope` | `<your-server-ip>` |
| A | `api.mailscope` | `<your-server-ip>` |

---

## 9. Verify the Deployment

```bash
# Frontend loads
curl -I https://mailscope.dpdns.org

# Backend health
curl https://api.mailscope.dpdns.org/api/health

# Backend CORS header present
curl -H "Origin: https://mailscope.dpdns.org" \
     -I https://api.mailscope.dpdns.org/api/health
# → Should include: Access-Control-Allow-Origin: https://mailscope.dpdns.org
```

---

## 10. Local Development (unchanged)

```powershell
.\start.ps1
# Backend: http://localhost:8001
# Frontend: http://localhost:5173
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| 401 on all API calls | `SUPABASE_JWT_SECRET` not set | Check `backend/.env` |
| CORS error in browser | `ALLOWED_ORIGINS` missing production URL | Add `https://mailscope.dpdns.org` to `ALLOWED_ORIGINS` |
| TShark not found | TShark not installed in container | Dockerfile installs it; rebuild image |
| 413 on large PCAP upload | nginx `client_max_body_size` too small | Already set to 105M in `nginx.conf` |
| WebSocket upgrade fails | Missing `Upgrade` header in nginx proxy | Already configured in `nginx.conf` |
