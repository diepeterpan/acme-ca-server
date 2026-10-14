# ACME CA Server &mdash; UI Tour & Screen Showcase

Welcome to the visual documentation for **ACME CA Server**. This guide captures the entire web user experience, covering authentication, first-boot onboarding workflows, administrative management screens, and the updated accounts and order diagnostics views.

To re-generate or update these captures at any time, run:
```bash
./scripts/capture_ui_screens.py
```

---

## Table of Contents
1. [Authentication & Onboarding](#1-authentication--onboarding)
   - [01. Login Screen](#01-login-screen)
   - [02. Initial Admin Onboarding](#02-initial-admin-onboarding)
   - [03. Root CA Certificate Setup & Onboarding](#03-root-ca-certificate-setup--onboarding)
2. [Administrative Views & Audit Logs](#2-administrative-views--audit-logs)
   - [04. Home Dashboard](#04-home-dashboard)
   - [05. Root CA Certificate Details](#05-root-ca-certificate-details)
   - [06. Certificates Audit Log](#06-certificates-audit-log)
   - [07. Domains Registry](#07-domains-registry)
   - [08. Accounts Management](#08-accounts-management)
   - [09. Account Orders & Error Details Modal](#09-account-orders--error-details-modal)

---

## 1. Authentication & Onboarding

### 01. Login Screen
The entry authentication gateway features a branded purple shield icon, floating credential inputs, persistent "Remember Me" session support, and styled feedback alerts.

![Login Screen](screenshots/01_login_screen.png)

---

### 02. Initial Admin Onboarding
When running a clean instance without environment-seeded credentials, navigating to `/setup` prompts operators to initialize administrative credentials.

![Initial Admin Setup](screenshots/02_admin_setup_onboarding.png)

---

### 03. Root CA Certificate Setup & Onboarding
If the internal Certificate Authority has not yet been initialized, navigating to `/ca` or `/ca/setup` opens this guided configuration interface. Operators can define:
- **Distinguished Name Details**: Common Name, Organization, Country, State, Locality.
- **Cryptographic Settings**: Key Algorithm (RSA 2048/4096 or ECDSA curves P-256/P-384/P-521) and Hash Digest (SHA-256, SHA-384, SHA-512).
- **Validity Duration**: Configurable certificate validity in years.

![Root CA Setup & Onboarding](screenshots/03_ca_certificate_onboarding.png)

---

## 2. Administrative Views & Audit Logs

### 04. Home Dashboard
The central operational overview for operators:
- **ACME Entrypoint Hero Card**: Instant one-click copy of the active ACME directory URL (`http://localhost:8080/directory` or configured external domain) for configuring Certbot, Caddy, Traefik, or the bundled bash test harness.
- **Live KPI Counter Cards**: Real-time totals for Valid Certificates, Monitored Domains, Active Accounts, and Pending Orders.
- **Quick Links**: Direct shortcuts to inspect certificates, domains, CA details, and accounts.

![Home Dashboard](screenshots/04_home_dashboard.png)

---

### 05. Root CA Certificate Details
The active Certificate Authority screen with a **40% left / 60% right** proportional layout:
- **Left Column (40%)**: Serial Number and Cryptographic Key & Digest.
- **Right Column (60%)**: Subject Distinguished Name and Validity Period countdown.
- **Full Width**: SHA-256 Fingerprint.
- **Download Buttons**: Immediate download of the active Root Certificate (`.crt`) and Certificate Revocation List (`.crl`).
- **PEM Viewer**: In-browser inspection and one-click copy of the raw PEM CA certificate.

![Root CA Certificate Details](screenshots/05_ca_certificate.png)

---

### 06. Certificates Audit Log
Comprehensive log of all certificates issued by the ACME server:
- Filterable by status tabs: **All**, **Valid**, **Revoked**, **Expired**.
- Real-time text search by domain, common name, or serial number.
- Direct download of individual leaf certificates and certificate chains.
- Revocation management and validity timeline tracking.

![Certificates Audit Log](screenshots/06_certificates_log.png)

---

### 07. Domains Registry
Registry of all Fully Qualified Domain Names (FQDNs) managed by ACME clients:
- Tracks first request timestamp and current certificate expiration date.
- Status badges indicating domain validity.
- Direct link (`View Certificates →`) to inspect all certificates associated with a specific domain.

![Domains Registry](screenshots/07_domains_log.png)

---

### 08. Accounts Management
Management center for all registered ACME client accounts:
- Displays Account ID (`kid`), contact email, and public key type (RSA/ECDSA).
- Certificate breakdown counters: **Valid**, **Revoked**, and **Expired**.
- Order request breakdown counters: **Valid**, **Pending**, **Processing**, and **Errors**.
- **Non-wrapping Registered column** ensuring clean tabular alignment.
- Administrative actions to toggle account status between **Valid** and **Deactivated**.

![Accounts Management](screenshots/08_accounts_log.png)

---

### 09. Account Orders & Error Details Modal
Triggered by clicking on the order error pill or the **Orders** button for any account:
- **Descending Order Sort**: Orders are strictly ordered by `expires_at` descending, placing the most recent orders at the top.
- **Clear Expiration Display**: Shows formatted timestamp (`📅 Expires: YYYY-MM-DD HH:MM:SS`) and flags expired orders with a distinct badge.
- **Domain Pills**: Lists all domain identifiers associated with each order request.
- **Detailed Error Box**: Pinpoints validation failures (e.g., DNS NXDOMAIN, connection refused, unauthorized) directly from the underlying ACME challenges.

![Account Orders & Error Details Modal](screenshots/09_account_orders_modal.png)
