# Secure Vault Pro

Production-style **file vault dashboard** built with **PHP + PostgreSQL + Redis** (XAMPP-ready).

Secure Vault Pro gives you:
- Role-based login (`admin`, `user`)
- Policy-enforced uploads (images/docs)
- PostgreSQL metadata + Redis cache/rate-limit
- Admin panel for user management + moderation
- Audit logs for sensitive actions
- Fast listing queries with CTE + window functions + indexes

## Why This Project

Most upload demos are too basic. This one is designed as a reusable starter template for:
- capstone projects
- internship assignments
- secure internal file tools
- backend + security portfolio demonstrations

## Core Features

### User Side
- Login/logout with session hardening
- Upload files with policy acknowledgment
- Search + filter by name/uploader/category
- Download own files securely
- Visual dashboard with 7-day upload trend

### Admin Side
- Full admin panel
- Create users (`admin` or `user`)
- Enable/disable users
- Disable/restore assets
- View recent audit logs

### Security & Reliability
- CSRF protection on state-changing forms
- Upload rate limiting per IP (Redis)
- Login rate limiting per IP (Redis)
- Extension + MIME validation (double-check)
- Randomized storage filename
- SHA-256 fingerprint stored for each file
- Download authorization checks
- Path traversal protection
- `X-Content-Type-Options: nosniff`

### Performance
- Indexed PostgreSQL tables
- CTE + window-function list query
- Redis cache keys versioned with invalidation
- Dashboard aggregates cached

## Stack
- PHP 8.x (XAMPP)
- PostgreSQL 14+
- Redis 6+
- Plain CSS (modern dashboard design)

## Project Structure

```txt
secure-vault-pro/
├─ app/
│  ├─ config.php
│  └─ bootstrap.php
├─ public/
│  ├─ login.php
│  ├─ logout.php
│  ├─ index.php
│  ├─ download.php
│  └─ assets/app.css
├─ sql/schema.sql
├─ storage/
│  ├─ uploads/
│  └─ logs/
├─ .env.example
└─ README.md
```

## Quick Start (XAMPP)

1. Place repo in XAMPP htdocs:
   - `/opt/lampp/htdocs/secure-vault-pro`
2. Ensure writable storage:
   - `sudo chown -R daemon:daemon /opt/lampp/htdocs/secure-vault-pro/storage`
3. Make sure PostgreSQL + Redis are running.
4. Open:
   - `http://localhost/secure-vault-pro/public/login.php`

## Default Credentials (for first login)

- **Admin:** `aryan@example.com` / `Admin@12345`
- **Users:** existing users in `app_users` get seeded password `User@12345`

Change passwords immediately in real deployments.

## Database Notes

This project auto-applies schema upgrades at boot (`app/bootstrap.php`) and also includes SQL script:
- `sql/schema.sql`

## Make This Your Own

- Add email verification
- Add virus scanning (ClamAV)
- Add S3/MinIO storage backend
- Add JWT API for frontend/mobile apps
- Add Docker Compose for one-command setup

## Template Usage

This repository is intended to be marked as a **GitHub template** so others can click **Use this template** and start quickly.

## License

MIT
