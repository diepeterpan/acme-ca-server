# ACME CA Server

[![Build](https://github.com/knrdl/acme-ca-server/actions/workflows/docker-image.yml/badge.svg)](https://github.com/knrdl/acme-ca-server/actions/workflows/docker-image.yml)

A self-hosted ACME server with a built-in CA and optional web interface.

## Features

* ✅ **ACME Server** implementation (supports `http-01` and `dns-01` challenges, including wildcard certificates)
* 🔐 **Built-in CA** to sign/revoke certificates (can be replaced with an external CA), CA rollover is supported
* 📡 **OpenWrt Router Integration** &mdash; One-command automated configuration (`run_openwrt_config.sh`) for OpenWrt routers: configures `acme.sh` with dynamic `dnsmasq` hooks for zero-touch RFC 8555 `dns-01` wildcard issuance, cleans stale static TXT entries, sets up daily renewal checks, and preserves scripts across sysupgrades.
* ✉️ **Mail notifications** (for account creation, expiring and expired certificates) with customizable templates
* 🌐 [**Web UI**](./Documentation/UI_TOUR_SHOWCASE.md) &mdash; Modern, full-featured administrative web interface ([view screenshot showcase](./Documentation/UI_TOUR_SHOWCASE.md)):
  * 📊 **Operational Dashboard**: Live KPI metrics (certificates, domains, accounts, orders) and ACME Entrypoint hero card with 1-click clipboard copy.
  * 🏛️ **Root CA Management**: Proportional 40%/60% details view with certificate and CRL downloads, validity countdown, and PEM viewer.
  * 📜 **Certificates & Domains**: Searchable audit logs with status tabs (Valid, Revoked, Expired) and direct downloads.
  * 👥 **Accounts Management**: ACME account registry (`kid`), certificate/order breakdowns, activate/deactivate actions, and interactive order error diagnostics with descending expiration sorting.
  * ✉️ **Mail Settings & Delivery Test**: Dedicated UI screen to configure outbound SMTP parameters, warning policies, and run live connection tests before saving.
  * 🔒 **Session Authentication**: Secure PBKDF2-hashed login, Remember Me sessions, and guided first-boot onboarding.

Tested with [Certbot](https://certbot.eff.org/), [Traefik](https://traefik.io/traefik/), [Caddy](https://caddyserver.com/), [uacme](https://github.com/ndilieto/uacme), [acme.sh](https://github.com/acmesh-official/acme.sh).

## Setup
### 1. Generate a new CA root certificate (or use an existing one)

You can generate a new root CA key and certificate using OpenSSL:

```shell
openssl genrsa -out ca.key 4096
openssl req -new -x509 -nodes -days 3650 -subj "/C=DE/O=Demo" -key ca.key -out ca.pem
````

These two files (`ca.key` and `ca.pem`) will be imported into the container on first startup.

> The container runs as a non-root user, so it must be able to read the key and certificate files.
> Make sure the permissions are set correctly:
>
> ```shell
> chmod 600 ca.key ca.pem  # protect key from other users
> chown 1000:1000 ca.key ca.pem  # ensures correct ownership
> ```

Once imported successfully, the CA data is stored in the database and you can remove the key files.


### 2. Deploy the container

Docker Compose snippet:

```yaml
services:

  acme-ca-server:
    image: knrdl/acme-ca-server
    restart: always
    environment:
      EXTERNAL_URL: https://acme.mydomain.org
      DB_DSN: postgresql://postgres:secret@db/postgres
    networks:
      - db_net
      - reverse_proxy_net
    volumes:
      - ./ca.key:/import/ca.key:ro # needed once to import new ca
      - ./ca.pem:/import/ca.pem:ro # needed once to import new ca
    mem_limit: 250m

  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_PASSWORD: secret  # use a strong password: `openssl rand -hex 32`
    networks:
      - db_net
    volumes:
      - ./db:/var/lib/postgresql/data
    mem_limit: 250m

networks:
  db_net:
  reverse_proxy_net:  # see next step
```

### 3. Reverse proxy

Serve the app securely using a TLS-terminating reverse proxy (like Apache, Nginx, Traefik or Caddy), e.g. at https://acme.mydomain.org

The app listens on port **8080** for HTTP traffic.

> For a quick test you can skip the reverse proxy and expose the service directly:
> ```yaml
> services:
>   acme-ca-server:
>     # ...
>     environment:
>       EXTERNAL_URL: http://localhost:8080
>     # ...
>     ports:
>       - "8080:8080"
>     # ...
> ```
> Don't do this in production. TLS usage is advised.

### 4. Test with certbot

```shell
docker run -it --rm certbot/certbot certonly --server https://acme.mydomain.org/acme/directory --standalone --no-eff-email --email user1@mydomain.org -v --domains test1.mydomain.org
```

## Customizations

### Environment Variables

> [Docker Secrets](https://docs.docker.com/reference/cli/docker/secret/) can also be used, ideal for sensitive values like `CA_ENCRYPTION_KEY` and `DB_DSN`.
For instance, `DB_DSN` can be provided either as an env var or as a file at `/run/secrets/DB_DSN` or `/run/secrets/db_dsn`.

| Env Var | Default | Description |
|---------|---------|-------------|
| EXTERNAL_URL        |         | The HTTPS address the server will be reachable from, e.g. https://acme.mydomain.org             |
| DB_DSN        |         | Postgres connection string, e.g. `postgresql://username:password@host/dbname` (the database will be initialized on startup)            |
| LOG_LEVEL | `info` | `debug`, `info`, `warning`, `error`  |
| ACME_TERMS_OF_SERVICE_URL        | `None`        | Optional URL which the ACME client can show when the user has to accept the terms of service, e.g. https://acme.mydomain.org/terms             |
| ACME_MAIL_REQUIRED        | `True`       | whether the user has to provide a mail address to obtain certificates via the ACME client (recommended)        |
| ACME_MAIL_TARGET_REGEX        | any mail address       | restrict the format of user-provided mail addresses. E.g. `[^@]+@mydomain\.org` only allows mail addresses from mydomain.org             |
| ACME_DNS_CHALLENGE_ENABLED    | `True`       | whether `dns-01` challenge validation is enabled                                                                 |
| ACME_HTTP_CHALLENGE_ENABLED   | `True`       | whether `http-01` challenge validation is enabled                                                                |
| ACME_DNS_RESOLVERS            | `[]`         | custom DNS resolvers for DNS-01 validation (e.g. `1.1.1.1:53,8.8.8.8:53`). Defaults to system DNS if empty      |
| ACME_ALLOW_WILDCARDS          | `True`       | allow requesting wildcard certificates (e.g. `*.mydomain.org`, fulfilled via `dns-01`)                           |
| ACME_TARGET_DOMAIN_REGEX      | domain regex | restrict the domain names for which certificates can be requested via ACME. Default: `(\*\.)?[^\*]+\.[^\.]+`   |
| CA_ENABLED        | `True`       | whether the internal CA is enabled, set this to false when providing a custom CA implementation  |
| CA_ENCRYPTION_KEY        | will be generated if not provided       | the key to protect the CA private keys at rest (encrypted in the database)  |
| CA_IMPORT_DIR        | `/import`       | where the *ca.pem* and *ca.key* are initially imported from, see 2. <br>CA rollover is as simple as placing a new cert and key in this directory. The server will detect and import them at startup. |
| CA_CERT_LIFETIME        | 60 days (`60d`)       | how often certs must be replaced by the ACME client  |
| CA_CERT_CDP_ENABLED    | `True` | Add CDP (Certificate Revocation List Distribution Point) URL to certificates, so clients SHOULD check certificates for revocation. When `False`, the CDP is omitted from certificates, preventing clients from checking revocation status and making revocation ineffective. |
| CA_CRL_LIFETIME        | 7 days (`7d`)       | how often the certificate revocation list will be rebuilt (despite rebuild on every certificate revocation)  |
| MAIL_ENABLED        | `False`       | if sending mails is enabled              |
| MAIL_HOST        | `None`       | SMTP host  |
| MAIL_PORT        | `None`       | SMTP port (default depends on encryption method)  |
| MAIL_USERNAME        | `None`       | SMTP auth username  |
| MAIL_PASSWORD        | `None`       | SMTP auth password  |
| MAIL_ENCRYPTION        | `tls`       | transport encryption method: <br>`tls` (recommended) <br> `starttls` <br> `plain` (unencrypted) <hr> `tls-nonstrict` `starttls-nonstrict` (on error: *Missing Authority Key Identifier*) |
| MAIL_SENDER        | `None`       | the mail address shown when sending mails, e.g. `acme@mydomain.org`  |
| MAIL_NOTIFY_ON_ACCOUNT_CREATION        | `True`       | whether to send a mail when the user runs ACME for the first time  |
| MAIL_WARN_BEFORE_CERT_EXPIRES        | 20 days (`20d`)     | when to warn the user via mail that a certificate has not been renewed in time (can be disabled by providing `false` as value)  |
| MAIL_NOTIFY_WHEN_CERT_EXPIRED        | `True`       | whether to inform the user that a certificate finally expired which has not been renewed in time  |
| WEB_ENABLED        | `True` | whether to also provide UI endpoints or just the ACME functionality |
| WEB_APP_TITLE        | `ACME CA Server` | title shown in web and mails  |
| WEB_APP_DESCRIPTION        | `Self-hosted ACME CA Server` | description shown in web and mails  |
| WEB_ADMIN_USERNAME        | `None` | optional username to pre-provision an initial web administrator account on startup (e.g. `admin`). If unset, credentials can be initialized via `/setup`. |
| WEB_ADMIN_PASSWORD        | `None` | optional initial password for the pre-provisioned administrator account. Supports Docker Secrets (`/run/secrets/web_admin_password`). |
| WEB_SESSION_SECRET        | `None` | optional HMAC secret key for signing session cookies (`acme_session`). Defaults to `CA_ENCRYPTION_KEY` if unset. |

### Configuration Precedence: Seed Variables vs. Authoritative Variables

The server distinguishes between **Seed Variables** (which initialize the database once) and **Authoritative Runtime Variables** (which always take precedence on every restart):

#### 1. Seed Values (Database Overrides on Future Starts)
These environment variables serve solely as **initial bootstrap defaults**. Once written to PostgreSQL, the database becomes the single source of truth:
* **Mail Settings (`MAIL_*`)**: `MAIL_ENABLED`, `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_ENCRYPTION`, `MAIL_SENDER`, `MAIL_NOTIFY_ON_ACCOUNT_CREATION`, `MAIL_WARN_BEFORE_CERT_EXPIRES`, `MAIL_NOTIFY_WHEN_CERT_EXPIRED`.
  * *Behavior*: On clean database installations, these seed the initial row in `mail_settings`. After initialization or after changes are saved via the Web UI (**Mail Settings** screen), the database values take precedence. Changing `MAIL_*` environment variables afterwards will **not** override stored database settings. To update mail settings, use the Web UI or update the `mail_settings` table directly.
* **Initial Admin Credentials (`WEB_ADMIN_*`)**: `WEB_ADMIN_USERNAME`, `WEB_ADMIN_PASSWORD`.
  * *Behavior*: Pre-provisions an initial administrator account on startup only if the username does not already exist in the database. If the user already exists, changing `WEB_ADMIN_PASSWORD` in the environment will **not** alter the existing password hash stored in the database.
* **CA Import Files (`CA_IMPORT_DIR`)**:
  * *Behavior*: Imports `ca.pem` and `ca.key` into the database if present. If omitted, the database's existing active CA certificate is utilized.

#### 2. Authoritative Runtime Variables (Always Override / Never in DB)
These variables are read directly from the environment on every startup and request; they are **never** overridden by database state:
* **Core & Infrastructure**: `DB_DSN`, `EXTERNAL_URL`, `LOG_LEVEL`.
* **Security & Encryption**: `CA_ENCRYPTION_KEY` (required to decrypt CA private keys stored at rest), `WEB_SESSION_SECRET` (session cookie signing).
* **CA Issuance Policies**: `CA_ENABLED`, `CA_CERT_LIFETIME`, `CA_CRL_LIFETIME`, `CA_CERT_CDP_ENABLED`.
* **ACME Restrictions & Policies**: `ACME_TERMS_OF_SERVICE_URL`, `ACME_MAIL_REQUIRED`, `ACME_MAIL_TARGET_REGEX`, `ACME_TARGET_DOMAIN_REGEX`.
* **Web UI Configuration**: `WEB_ENABLED`, `WEB_APP_TITLE`, `WEB_APP_DESCRIPTION`.

### Customize templates

#### Mail

Templates consist of `subject.txt` and `body.html` (see [here](./app/mail/templates)). Overwrite the following files:
* /app/mail/templates/**cert-expired-info**/{subject.txt,body.html}
* /app/mail/templates/**cert-expires-warning**/{subject.txt,body.html}
* /app/mail/templates/**new-account-info**/{subject.txt,body.html}

Template parameters:
* `app_title`: `str`  application title from `WEB_APP_TITLE`
* `app_desc`: `str`  application description from `WEB_APP_DESCRIPTION`
* `web_url`: `str`  web index url from `EXTERNAL_URL`
* `acme_url`: `str`  acme directory url
* `domains`: `list[str]` list of expiring domains
* `expires_at`: `datetime` domain expiration date
* `expires_in_days`: `int` days until cert will expire
* `serial_number`: `str` expiring certs serial number (hex)

#### Web UI

Custom files to be served by the http server can be placed in `/app/web/www`.

Overwrite templates (see [here](./app/web/templates)):
* /app/web/templates/index.html (Startpage / Dashboard)
* /app/web/templates/ca-details.html (Root CA Certificate & CRL Details)
* /app/web/templates/ca-setup.html (Root CA Setup & Onboarding)
* /app/web/templates/cert-log.html (Certificate Listing)
* /app/web/templates/domain-log.html (Domain Listing)
* /app/web/templates/account-log.html (Account Management & Error Modal)
* /app/web/templates/login.html (Sign-in Authentication Screen)
* /app/web/templates/setup.html (Initial Admin Account Setup)

Template parameters:
* `app_title`: `str`  application title from `WEB_APP_TITLE`
* `app_desc`: `str`  application description from `WEB_APP_DESCRIPTION`
* `web_url`: `str`  web index url from `EXTERNAL_URL`
* `acme_url`: `str`  acme directory url
* `certs`: `list` list of certs for `cert-log.html`
* `domains`: `list` list of domains for `domain-log.html`

### Provide a custom CA implementation

If you want to integrate your own CA logic, you can replace the default implementation used by the application.

> 💡 A complete example that retrieves certificates from an HTTP endpoint is available [here](https://github.com/knrdl/acme-ca-server/issues/247#issuecomment-3783583560)

First set env var `CA_ENABLED=False` to disable the built-in CA. Then overwrite the file `/app/ca/service.py` in the docker image. You can use the [existing file](./app/ca/service.py) as a reference. Your implementation must provide two functions:

#### 1. `sign_csr()`

```python
async def sign_csr(csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]) -> SignedCertInfo:
    ...
```

* `csr`: a [x509.CertificateSigningRequest](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.CertificateSigningRequest) object
* `subject_domain`: the main domain name for the certificate
* `san_domains`: *subject alternative names*, all domain names (including `subject_domain`) for the certificate
* *returns*: instance of `SignedCertInfo()`

```python
class SignedCertInfo:
    cert: x509.Certificate
    cert_chain_pem: str
```

* `cert`: a [x509.Certificate](https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate) object
* `cert_chain_pem`: a PEM-encoded text file containing the created cert as well as the root or also intermediate cert. This file will be used by the ACME client

#### 2. `revoke_cert()`

```python
async def revoke_cert(serial_number: str, revocations: set[tuple[str, datetime]]) -> None:
    ...
```

* `serial_number`: certificate serial number to revoke as hex value
* `revocations`: all revoked certificates including the one specified by `serial_number`. It's a set of tuples containing `(serial_number, revocation_date)`
* *returns*: no error on success, throw exception otherwise

A custom CA backend must also handle the CRL (certificate revocation list) distribution.

## Internals

### Entities

```mermaid
flowchart LR
    accounts -->|1:0..n| orders
    orders -->|1:1..n| authorizations
    authorizations -->|1:1| challenges
    orders -->|1:0..1| certificates
```

### Tests

```shell
cd tests/e2e
./run.sh
cd ../pytest
./run.sh
cd coverage
python3 -m http.server  # coverage report at localhost:8000
```

## Useful Scripts

The repository includes several standalone utility scripts to simplify development, testing, and documentation:

### 1. `acme_client.sh` &mdash; Pure Bash ACME Test Harness & Client

A zero-dependency, pure Bash interactive test harness and client implementing the RFC 8555 ACME protocol using standard CLI tools (`curl`, `openssl`, `jq`, `python3`). It provides end-to-end certificate lifecycle workflows (new issuance, renewal, revocation, account key rollover, ARI renewal info) and individual ACME API primitive tests.

**Key capabilities:**
* **Challenge Support**:
  * **HTTP-01**: Integrated standalone HTTP responder on custom/configurable ports with automatic `sudo` elevation for privileged ports (e.g. port 80). Challenge files are deployed to `.acme_workspace/www/.well-known/acme-challenge/`.
  * **DNS-01 & Wildcards**: Full support for wildcard certificates (`*.example.com`) and standard domains using DNS-01. The client automatically calculates the RFC 8555 SHA-256 base64url digest of the key authorization and interactively displays the exact DNS TXT record details (`_acme-challenge.<domain>`), pausing until propagation is complete before triggering validation.
* **On-Demand Challenge Server**: The standalone HTTP-01 challenge responder only starts when an HTTP-01 challenge is actually required. Wildcard-only orders proceed directly to DNS-01 without prompting for HTTP server privileges.
* **Certificate Lifecycle Workflows**:
  * Request new certificates with custom validity ranges (`notBefore` and `notAfter`).
  * Renew existing certificates with automatic domain discovery, private key reuse or re-generation, and ACME Renewal Information (ARI, RFC 9444) queries.
* **ACME Protocol Test Suite**: Interactive execution of individual ACME API primitives (Directory fetching, New-Nonce, Account creation/update, Key-Change rollover per RFC 8555 §7.5, Order creation, Authorization polling, Challenge triggering, CSR Finalization, Certificate download, and Revocation).

**Interactive Usage:**
```shell
# Launch the interactive menu (options [1-6])
./acme_client.sh

# Or via the symlink
./acme_test_harness.sh
```

#### DNS-01 Challenge & Wildcards Workflow

When requesting a certificate for a wildcard domain (e.g., `*.example.com`) or when the CA requires DNS validation:

1. **Automatic Challenge Selection**: Per RFC 8555, wildcard domains require `dns-01`. `acme_client.sh` automatically detects the wildcard identifier and selects the `dns-01` challenge.
2. **Digest Calculation**: The client derives the account thumbprint, constructs the key authorization (`token.thumbprint`), and calculates the base64url-encoded SHA-256 digest:
   $$\text{TXT Value} = \text{base64url}(\text{SHA-256}(\text{keyAuthorization}))$$
3. **Interactive Deployment Prompt**: The client displays the exact record name and value to publish in your DNS zone:
   ```
   [!] DNS-01 Challenge: Please deploy the following DNS TXT record:
     Host / Name:  _acme-challenge.example.com
     TXT Value:    HVFIxLEqgP4vy-1TT6f3h1H3RJTUleGA0Uwh0XDv9TU
   Press Enter once the TXT record has been deployed...
   ```
4. **Validation & Finalization**: After creating the TXT record in your DNS provider and pressing <kbd>Enter</kbd>, `acme_client.sh` notifies the CA server to validate the challenge, polls the authorization status until valid, submits the CSR, and saves `fullchain.pem` and `privkey.pem` to `.acme_workspace/certs/<domain>/`.

##### Example: Deploying DNS-01 TXT Record on OpenWrt 25 (`dnsmasq`)

If your local DNS is managed by an **OpenWrt 25** router/gateway running `dnsmasq`, you can configure the challenge TXT record directly via SSH or the router console:

1. Edit `/etc/config/dhcp`:
   ```shell
   nano /etc/config/dhcp
   ```
   Under the `config dnsmasq` section, add or update the `extraconftext` option with your domain and challenge digest:
   ```text
   option extraconftext 'txt-record=_acme-challenge.domain.com,"FVjqY3EYMomWyBOsJpj0ozekNUgALVIwmitoWaiHV40"'
   ```

2. Restart `dnsmasq` to apply the changes:
   ```shell
   /etc/init.d/dnsmasq restart
   ```

3. Verify that the TXT record is being resolved:
   ```shell
   nslookup -type=txt _acme-challenge.domain.com 127.0.0.1
   ```

*(Note: `acme_test_harness.sh` is provided as a convenient symlink to `acme_client.sh`)*

> [!TIP]
> For fully automated, zero-touch certificate issuance and renewal on OpenWrt (without manually editing `/etc/config/dhcp`), use the [`run_openwrt_config.sh`](#2-run_openwrt_configsh--openwrt-router-acme-client--dnsmasq-automation) configurator described below.

---

### 2. `run_openwrt_config.sh` &mdash; OpenWrt Router ACME Client & Dnsmasq Automation

An automated, interactive configuration tool that provisions an OpenWrt router to issue and renew RFC 8555 certificates (including wildcard domains) directly against your local ACME CA server using dynamic `dnsmasq` DNS-01 challenge hooks.

**Key capabilities:**
* **Safety & Preview Guard**: Includes an author warranty waiver / liability disclaimer prompt, `--dry-run` simulation mode, non-interactive disclaimer acceptance (`-y` / `--yes` / `--accept-terms`), and an explicit confirmation gate with full command previews before applying any configuration changes or executing mutations on the router.
* **Granular Overwrite & Re-Apply Prompts**: Everywhere files or settings are targeted on OpenWrt, the script checks if files exist, checks if contents match (via MD5 hashing), and prompts whether to overwrite or skip. If configurations (UCI global settings, dnsmasq confdir, boot scripts in `rc.local`, cron tables) are already configured, it prompts whether to re-apply/overwrite or skip.
* **Dual SSH Authentication & Connection Multiplexing**: Connects using standard SSH public keys (with automatic discovery) or password authentication (`sshpass` / interactive prompt). Reuses an OpenSSH `ControlMaster` multiplexed connection for instant execution across multiple commands without re-prompting.
* **Package Manager Auto-Detection**: Dynamically detects the package manager (modern OpenWrt 25.12+ `apk` vs. legacy `opkg`), verifies installed dependencies (`luci-app-acme`, `acme-acmesh`, `curl`, `ca-certificates`), incorporates direct binary fallbacks, and builds targeted installation commands.
* **Smart State Management**: Automatically remembers router hostname, user, port, domain, account email, and CA URL in a local config file (`.openwrt_config.env`), which is automatically ignored by Git.
* **ACME Account Email & Debug Logging**: Discovers existing `account_email` on OpenWrt across named (`acme.acme1`, `acme.acme`) and indexed (`acme.@acme[0]`) sections, checks if values already match, and enables verbose debug logging (`option debug '1'` on OpenWrt and `--debug` in `acme.sh`).
* **Zero-Touch Dynamic DNS-01 Hook**:
  * Configures `dnsmasq` dynamic `confdir='/tmp/acme'` (supporting both `@dnsmasq[0]` and named sections like `dnsmasq1`).
  * Automatically provisions boot startup (`/etc/rc.local`) to recreate `/tmp/acme` and restart `dnsmasq` on router boot.
  * Deploys native `acme.sh` DNS API plugin `/etc/acme/dnsapi/dns_openwrt_dnsmasq.sh` (symlinked into `/usr/lib/acme/client/dnsapi/`, `/usr/lib/acme/dnsapi/`, and `/root/.acme.sh/dnsapi/`) to dynamically write temporary challenge files (`/tmp/acme/acme_<domain>_<token>.conf`) with collision-proof concurrent wildcard + apex support, self-heals `/tmp/acme` directory creation, and triggers `/etc/init.d/dnsmasq restart`.
  * Automatically detects and prompts to clean legacy static `option extraconftext 'txt-record=...'` entries from `/etc/config/dhcp` to avoid challenge conflicts.
* **Wildcard & Apex Domain Support**: Automatically maps and issues certificates covering both `*.<domain>` and `<domain>`, enabling single-certificate encryption for both router web administration (`uhttpd`) and network services.
* **CA Trust Auto-Upload**: Checks router connectivity to your local ACME CA server, detecting SSL certificate verification issues and offering to upload the local or user-specified root CA certificate (`ca.pem`) directly to OpenWrt's trust store (`/etc/ssl/certs/local-ca.pem`) with `c_rehash`.
* **Pre-Flight DNS-01 Resolution Verification**: Deploys a temporary probe TXT record (`_acme-challenge-test.<domain>`), verifies local resolution on the router (`nslookup`), and validates query propagation from the host machine against the router (`<ROUTER_HOST>:53` via Python dnspython or `dig`) before requesting certificates from the CA.
* **Interactive Issuance & LuCI Web Integration**: Discovers the router's `acme.sh` binary, creates a `/usr/bin/acme.sh` convenience symlink, checks for existing certificates, and explicitly prompts whether to issue, force-renew, or skip before running `--issue` with automatic `uhttpd` reloading.
* **Automated Daily Renewal & Sysupgrade Backup Protection**:
  * Deploys `/usr/bin/acme-renew-check.sh` (with self-healing `/tmp/acme` creation) and registers a daily cron job (`03:15`) with automatic `uhttpd` reload on renewal.
  * Registers `/etc/rc.local`, `/etc/acme` (all issued certificates, account keys, and DNS API plugins), `/etc/ssl/certs/local-ca.pem` (custom CA trust), `/usr/bin/acme-renew-check.sh`, and `/etc/crontabs/root` in `/etc/sysupgrade.conf` so all ACME configurations, trust certificates, and keys survive OpenWrt firmware upgrades and backups.
* **Session Logging & Interactive Viewer**: Streams colored output to the console and records a full timestamped log to `.acme_workspace/logs/`, offering an interactive log viewer (`less` / `cat`) upon completion.
* **Plugin Unit Testing**: Includes `tests/test_dns_openwrt_dnsmasq.sh` to validate the POSIX `/bin/sh` plugin logic, token slugging, wildcard + apex coexistence, and selective record cleanup.

**CLI Options:**

| Option | Description | Default |
| :--- | :--- | :--- |
| `-d`, `--dry-run` | Simulate all operations without modifying the OpenWrt router | `false` |
| `-y`, `--yes`, `--accept-terms` | Accept disclaimer and liability terms without interactive prompt | `false` |
| `-h`, `--help` | Show usage and CLI help message | |
| `--host <HOST>` | OpenWrt router IP or hostname | `192.168.1.1` |
| `--user <USER>` | OpenWrt SSH username | `root` |
| `--port <PORT>` | OpenWrt SSH port | `22` |
| `--ca-url <URL>` | ACME CA directory URL (auto-appends `/acme/directory`) | `https://your-local-ca.lan/acme/directory` |
| `--domain <DOMAIN>` | LAN domain or wildcard (e.g., `lan`, `*.home.arpa`) | Detected from router |
| `--email <EMAIL>` | ACME account contact email | `admin@<domain>` |
| `--ca-cert <PATH>` | Path to local root CA certificate to upload if untrusted | `./ca.pem` |

**Usage Examples:**

```shell
# Run interactive wizard (prompts for options, credentials, and confirmation)
./run_openwrt_config.sh

# Run dry-run simulation mode to preview remote commands without modifying OpenWrt
./run_openwrt_config.sh --dry-run

# Run non-interactively in scripts (pre-accepting disclaimer terms)
./run_openwrt_config.sh --yes --host 192.168.1.1 --ca-url https://ca.local/acme/directory --domain *.lan

# Specify full router, CA URL, certificate, and account email parameters via CLI flags
./run_openwrt_config.sh --host 192.168.1.1 --user root --ca-url https://acme.mydomain.org --domain *.home.arpa --email admin@home.arpa --ca-cert ./ca.pem

# Run the plugin unit & integration test suite
./tests/test_dns_openwrt_dnsmasq.sh
```

---

### 3. `run_local.sh` &mdash; Local Dev Server & Database Bootstrapper

A one-command setup script to run the server locally for development without building Docker images manually.

**Key capabilities:**
* Automatically checks or creates a Python virtual environment (`.venv`).
* Installs and verifies dependencies from `requirements.txt`.
* Automatically provisions and starts a local PostgreSQL development container via Docker or Podman (`compose.dev.yml`).
* Applies database migrations up to the current schema.
* Starts `uvicorn` development server with auto-reload (`--reload`) on port 8080.

**Usage:**
```shell
# Start local development environment (default: http://0.0.0.0:8080)
./run_local.sh

# Run on a custom port or host
PORT=9000 HOST=127.0.0.1 ./run_local.sh
```

---

### 4. `run_tests.sh` &mdash; Local CI / Test Suite Runner (Pytest & E2E)

Replicates the GitHub Actions test workflow ([.github/workflows/tests.yml](.github/workflows/tests.yml)) locally. Exits with standard return codes (`0` on success, non-zero on failure) for consumption in CI pipelines, automation scripts, and git hooks.

**Key capabilities:**
* Automatically executes the **Pytest** unit/integration suite (`tests/pytest/run.sh`) and the **End-to-End** client compatibility suite (`tests/e2e/run.sh`).
* Flexible target selection: run both suites (`all`) or isolate individual suites (`pytest` or `e2e`).
* Automatically detects whether Docker commands require `sudo` or run directly under the current user permissions (with manual `--sudo` and `--no-sudo` flags).
* Built-in `--fail-fast` mode to immediately stop on the first suite failure.
* Includes `--no-cleanup` flag to preserve test containers and networks for post-failure inspection and debugging.
* Generates a concise execution summary displaying individual suite durations and overall pass/fail status.

**Usage:**
```shell
# Run all test suites (pytest + e2e)
./run_tests.sh

# Run only the pytest suite
./run_tests.sh pytest

# Run only the end-to-end client suite
./run_tests.sh e2e

# Stop immediately if a suite fails
./run_tests.sh --fail-fast

# Retain test containers upon failure for debugging
./run_tests.sh --no-cleanup
```

---

### 5. `run_lint.sh` &mdash; Code Quality & Lint Checks

Replicates the GitHub Actions linting workflow ([.github/workflows/lint.yml](.github/workflows/lint.yml)) locally, performing static analysis, security auditing, type checking, and spell checking.

**Key capabilities:**
* Activates or configures the Python virtual environment (`.venv`).
* Installs and verifies all linting tools: **Ruff**, **Flake8** (with security and best-practice plugins), **Pylint**, and **Mypy**.
* Automatically detects fixable errors in **Ruff** and offers an interactive `--fix` prompt.
* Automatically downloads and runs the **Typos** binary for fast codebase spell checking according to `_typos.toml`.
* Returns a total error count and exits with standard success (`0`) or failure (`1`) codes.

**Usage:**
```shell
# Run all lint checks
./run_lint.sh
```

---

### 6. `run_release.sh` &mdash; Release Workflow & Git Tagging

An interactive script to safely create, update, and push git release tags to trigger automated release workflows.

**Key capabilities:**
* Performs pre-release safety checks to ensure the git working tree is clean.
* Automatically executes `run_lint.sh` before allowing a release to proceed.
* Displays recent release tags and prompts for the next semver tag.
* Supports creating annotated or lightweight tags, updating tag messages, or re-pushing existing tags to `origin`.
* Automatically pushes tags to GitHub to trigger [.github/workflows/release.yml](.github/workflows/release.yml).

**Usage:**
```shell
# Run release workflow
./run_release.sh
```

---

### 7. `scripts/capture_ui_screens.py` &mdash; Automated UI Screen Capture Utility

A Playwright-driven automation utility that captures high-resolution screenshots of all 9 application screens (including unauthenticated login, first-boot onboarding, dashboard, 40/60 CA details, audit logs, and the account orders & error modal).

**Key capabilities:**
* Automatically generates signed session cookies to capture both guest and authenticated administrative screens.
* **Automatic Privacy Obfuscation**: Sanitizes real personal email addresses (`admin@example.com`), domain names (`app.example.com`), and Subject DN location fields with generic demonstration data (disable with `--no-obfuscate`).
* Interacts with UI components (e.g. opens the Order Requests & Error modal with descending expiration sorting).
* Automatically updates images in `Documentation/screenshots/` to keep [Documentation/UI_TOUR_SHOWCASE.md](./Documentation/UI_TOUR_SHOWCASE.md) fresh.

**Usage:**
```shell
# Capture all UI screens and save to Documentation/screenshots/
./scripts/capture_ui_screens.py

# Custom target server or custom output folder
./scripts/capture_ui_screens.py --base-url http://localhost:8080 --output-dir Documentation/screenshots
```


