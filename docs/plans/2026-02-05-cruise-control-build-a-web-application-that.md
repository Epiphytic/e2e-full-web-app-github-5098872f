# SQLite Database Editor Web Application - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust web application with htmx frontend that allows authenticated users to create, modify, and delete SQLite tables and their structures, secured with JWT authentication.

**Architecture:** Axum-based Rust backend serves htmx-powered HTML templates (via Askama) and a REST/hypermedia API for SQLite schema operations. JWT authentication uses a local CA with RS256 keys, exposing a `.well-known/jwks.json` endpoint. Playwright E2E tests validate the full user flow. GitHub Actions provides CI/CD with linting and dependency review.

**Tech Stack:** Rust (Axum, rusqlite, jsonwebtoken, askama), htmx, Playwright, GitHub Actions (super-linter, dependency-review-action)

---

## Overview

The application is a web-based SQLite database editor. Users authenticate via JWT tokens (RS256-signed by a local CA), then interact with an htmx-powered UI to manage database tables: creating/removing tables, and adding/removing columns. The backend uses Axum for HTTP handling, rusqlite for direct SQLite manipulation, and Askama for server-side HTML templating that htmx swaps in dynamically.

### Key Architectural Decisions

1. **Axum over Actix-web**: Simpler extractor-based API, excellent tokio integration, composable middleware via Tower.
2. **rusqlite over sqlx**: We're doing dynamic schema DDL (CREATE TABLE, ALTER TABLE, DROP TABLE) which doesn't benefit from sqlx's compile-time checking. rusqlite's synchronous API is simpler for DDL operations. We wrap it with `tokio::task::spawn_blocking` for async compatibility.
3. **RS256 JWT**: Local private key signs tokens; public key exposed via JWKS endpoint. The backend only needs the public key for verification.
4. **Askama templates**: Compile-time checked templates that integrate well with Axum and produce htmx-friendly HTML fragments.

### Directory Structure

```
.
├── .github/
│   └── workflows/
│       ├── lint.yml
│       ├── dependency-review.yml
│       └── e2e.yml
├── .gitignore
├── Cargo.toml
├── Cargo.lock
├── certs/
│   └── README.md          # Instructions only; actual keys and certificate generated at runtime
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── jwt.rs          # JWT validation, claims extraction
│   │   ├── jwks.rs         # JWKS endpoint handler
│   │   └── middleware.rs   # Axum auth middleware layer
│   ├── db/
│   │   ├── mod.rs
│   │   ├── connection.rs   # SQLite connection pool management
│   │   ├── schema.rs       # DDL operations (create/drop table, add/drop column)
│   │   └── queries.rs      # Read operations (list tables, describe table)
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── auth.rs         # Login page, token exchange
│   │   ├── tables.rs       # Table CRUD handlers
│   │   └── columns.rs      # Column CRUD handlers
│   └── templates/
│       (Askama templates live in project-root/templates/ per Askama convention)
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── table_list.html       # htmx partial
│   ├── table_detail.html     # htmx partial
│   ├── column_form.html      # htmx partial
│   └── table_form.html       # htmx partial
├── static/
│   └── htmx.min.js
├── tests/
│   └── e2e/
│       ├── package.json
│       ├── playwright.config.ts
│       ├── tsconfig.json
│       ├── helpers/
│       │   └── jwt.ts      # JWT token generation for tests
│       └── specs/
│           ├── auth.spec.ts
│           ├── tables.spec.ts
│           └── columns.spec.ts
├── scripts/
│   ├── generate-keys.sh    # Generate RSA key pair and self-signed X.509 certificate for JWT
│   └── run-e2e.sh          # Build server, start, run tests, stop
└── docs/
    └── plans/
        └── (this file)
```

---

## Risk Areas

1. **rusqlite + async**: rusqlite is synchronous. Every DB call must be wrapped in `spawn_blocking`. Forgetting this blocks the tokio runtime.
2. **ALTER TABLE limitations in SQLite**: SQLite doesn't support `DROP COLUMN` before version 3.35.0. Must ensure the bundled SQLite version supports it, or use the `bundled` feature of rusqlite.
3. **JWT key management**: Private keys and certificates must never be committed. The `.gitignore` must exclude `*.pem`, `*.key` files. Test keys and certificates should be generated dynamically.
4. **htmx CSRF**: htmx sends AJAX requests that bypass traditional CSRF protections. SameSite=Strict cookies alone are not sufficient for destructive DDL operations. Must implement explicit CSRF tokens: generate a per-session token server-side, embed it in templates via a `<meta>` tag, and configure htmx globally with `hx-headers='{"X-CSRF-Token": "..."}'` (or use `document.body.addEventListener("htmx:configRequest", ...)` to attach the token to every request). The server must validate the `X-CSRF-Token` header on all state-changing endpoints.
5. **SQL injection via table/column names**: Since we're building DDL dynamically, table and column names must be strictly validated (alphanumeric + underscore only) to prevent SQL injection.
6. **Playwright test flakiness**: Server startup race condition. Tests must wait for server health check before running.
7. **Super-linter configuration**: May flag Rust code style differently than `cargo clippy`. Need to configure linter rules to avoid false positives.
8. **Askama template compile-time errors**: Templates must be syntactically correct before integration - errors fail the entire build.
9. **CI build times**: Rust compilation is slow - cargo cache action is critical for acceptable CI performance.
10. **openssl dependency**: Required for key and certificate generation scripts only (not for JWKS parsing at runtime or tests). JWKS component extraction uses the `rsa` crate at server startup, and tests use the `rsa` + `rand` crates for keypair generation, eliminating any runtime or test dependency on the `openssl` CLI.

---

## Implementation Tasks

### Task CRUISE-001: Project Scaffolding and .gitignore

**Files:**
- Create: `.gitignore`
- Create: `Cargo.toml`
- Create: `src/main.rs` (minimal hello-world)

**Step 1: Create comprehensive .gitignore**

```gitignore
# Rust build artifacts
/target/
**/*.rs.bk
*.pdb

# Keys and credentials
*.pem
*.key
*.crt
*.p12
*.pfx
*.der
certs/*.pem
certs/*.key
certs/*.crt

# Environment files
.env
.env.*
!.env.example

# SQLite databases
*.db
*.sqlite
*.sqlite3

# Log files
*.log
logs/

# OS files - macOS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes

# OS files - Windows
ehthumbs.db
Thumbs.db
Desktop.ini
$RECYCLE.BIN/

# OS files - Linux
*~

# Editor/IDE files
.vscode/
.idea/
*.swp
*.swo
*.sublime-project
*.sublime-workspace
.project
.classpath
.settings/

# Node.js (for Playwright tests)
node_modules/
tests/e2e/node_modules/
tests/e2e/test-results/
tests/e2e/playwright-report/

# Fork-join directories
.fork-join/

# Temporary files
*.tmp
*.temp
*.bak
*.orig
```

**Step 2: Create minimal Cargo.toml**

```toml
[package]
name = "sqlite-editor"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

**Step 3: Create minimal src/main.rs**

```rust
use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/healthz", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Successful compilation

**Step 5: Commit**

```bash
git add .gitignore Cargo.toml Cargo.lock src/main.rs
git commit -m "feat: project scaffolding with .gitignore and minimal Axum server"
```

---

### Task CRUISE-002: JWT Key Generation and JWKS Endpoint

**Files:**
- Create: `scripts/generate-keys.sh`
- Create: `certs/README.md`
- Create: `src/auth/mod.rs`
- Create: `src/auth/jwt.rs`
- Create: `src/auth/jwks.rs`
- Modify: `Cargo.toml` (add jsonwebtoken, serde, serde_json, base64, rsa, chrono; add rand as dev-dependency for test keypair generation)
- Modify: `src/main.rs` (add JWKS route)

**Step 1: Create key generation script**

```bash
#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${1:-certs}"
mkdir -p "$CERT_DIR"

# Generate RSA 2048-bit private key
openssl genrsa -out "$CERT_DIR/private.pem" 2048

# Extract public key
openssl rsa -in "$CERT_DIR/private.pem" -pubout -out "$CERT_DIR/public.pem"

# Generate self-signed X.509 certificate (local JWT CA)
openssl req -new -x509 -key "$CERT_DIR/private.pem" \
  -out "$CERT_DIR/cert.pem" -days 365 \
  -subj "/CN=LocalJWTCA/O=Development"

echo "Keys and certificate generated in $CERT_DIR/"
echo "  private.pem - KEEP SECRET, used to sign JWT tokens"
echo "  public.pem  - Safe to distribute, used to verify JWT tokens"
echo "  cert.pem    - Self-signed X.509 certificate for local JWT CA"
```

**Step 2: Create certs/README.md**

```markdown
# JWT Signing Keys

Run `../scripts/generate-keys.sh` to generate keys and certificate.
Keys and certificate are .gitignored and must be generated locally.

Generated files:
- `private.pem` - RSA private key (keep secret, used to sign JWTs)
- `public.pem` - RSA public key (used to verify JWTs)
- `cert.pem` - Self-signed X.509 certificate (local JWT CA)
```

**Step 3: Add dependencies to Cargo.toml**

```toml
[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
jsonwebtoken = "9"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
rsa = { version = "0.9", features = ["pem"] }
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
rand = "0.8"
```

**Step 4: Write JWT validation module with tests**

Create `src/auth/jwt.rs`:

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn validate_token(token: &str, public_key_pem: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key_pem)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;

    fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("failed to encode private key PEM")
            .as_bytes()
            .to_vec();
        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode public key PEM")
            .as_bytes()
            .to_vec();

        (private_pem, public_pem)
    }

    #[test]
    fn test_validate_valid_token() {
        let (private_pem, public_pem) = generate_test_keypair();
        let claims = Claims {
            sub: "testuser".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };
        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(&private_pem).unwrap();
        let token = encode(&header, &claims, &key).unwrap();

        let result = validate_token(&token, &public_pem);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "testuser");
    }

    #[test]
    fn test_reject_expired_token() {
        let (private_pem, public_pem) = generate_test_keypair();
        let claims = Claims {
            sub: "testuser".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize,
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize,
        };
        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(&private_pem).unwrap();
        let token = encode(&header, &claims, &key).unwrap();

        let result = validate_token(&token, &public_pem);
        assert!(result.is_err());
    }
}
```

**Step 5: Run tests**

Run: `cargo test --lib auth::jwt`
Expected: 2 tests pass

**Step 6: Create JWKS endpoint handler**

Create `src/auth/jwks.rs` - parses RSA public key PEM and serves as JWK Set at `/.well-known/jwks.json`. Use the `rsa` crate to parse the PEM and extract modulus (n) and exponent (e) components at server startup, then cache the pre-computed JWKS response as application state. Encode components as base64url. This avoids shelling out to `openssl` CLI on each request. See full implementation in directory structure section.

**Step 7: Create auth/mod.rs**

```rust
pub mod jwt;
pub mod jwks;
pub mod middleware;
```

**Step 8: Wire JWKS into main.rs**

Add `/.well-known/jwks.json` route pointing to `auth::jwks::jwks_handler`. At startup, use the `rsa` crate to parse the public PEM and pre-compute the JWKS JSON response (extracting modulus and exponent), storing it as shared application state so the handler simply returns the cached response.

**Step 9: Commit**

```bash
git add scripts/ certs/README.md src/auth/ Cargo.toml Cargo.lock src/main.rs
git commit -m "feat: JWT validation and JWKS .well-known endpoint"
```

---

### Task CRUISE-003: JWT Auth Middleware

**Files:**
- Create: `src/auth/middleware.rs`
- Modify: `src/auth/mod.rs`

**Step 1: Create auth middleware**

`src/auth/middleware.rs` - Axum middleware that:
1. Extracts JWT from `Authorization: Bearer <token>` header
2. Falls back to extracting from `token=<value>` cookie
3. Validates token using `validate_token`
4. Injects `Claims` into request extensions
5. Returns 401 if no valid token found

```rust
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use super::jwt::{validate_token, Claims};

#[derive(Clone)]
pub struct AuthState {
    pub public_pem: Vec<u8>,
}

pub async fn require_auth(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request.headers()
                .get("Cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';').find_map(|c| c.trim().strip_prefix("token="))
                })
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = validate_token(token, &auth_state.public_pem)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
```

**Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add src/auth/
git commit -m "feat: JWT auth middleware with Bearer and cookie support"
```

---

### Task CRUISE-004a: SQLite Connection and Query Helpers

**Files:**
- Create: `src/db/mod.rs`
- Create: `src/db/connection.rs`
- Create: `src/db/queries.rs`
- Modify: `Cargo.toml` (add rusqlite)

**Step 1: Add rusqlite to Cargo.toml**

```toml
rusqlite = { version = "0.32", features = ["bundled"] }
```

The `bundled` feature ensures SQLite 3.45+ is included, which supports `ALTER TABLE DROP COLUMN`.

**Step 2: Write connection pool**

`src/db/connection.rs` - `DbPool` struct wrapping `Mutex<Connection>` with `with_conn` method for safe access.

**Step 3: Write query helpers**

`src/db/queries.rs` - Functions:
- `list_tables(conn) -> Vec<TableInfo>` - excludes sqlite_* internal tables
- `describe_table(conn, table_name) -> Vec<ColumnInfo>` - uses PRAGMA table_info

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/db/ Cargo.toml Cargo.lock
git commit -m "feat: SQLite connection pool and query helpers"
```

---

### Task CRUISE-004b: SQLite DDL Operations with Identifier Validation

**Files:**
- Create: `src/db/schema.rs`
- Modify: `src/db/mod.rs`

**Step 1: Write identifier validation**

Critical for SQL injection prevention. Only allows `[a-zA-Z_][a-zA-Z0-9_]*` and rejects SQLite reserved words.

**Step 2: Write DDL operations with tests**

`src/db/schema.rs` - Functions:
- `validate_identifier(name: &str) -> Result<(), String>` - SQL injection prevention
- `validate_column_type(col_type: &str) -> Result<(), String>` - whitelist: TEXT, INTEGER, REAL, BLOB, NUMERIC
- `create_table(conn, table_name, columns: &[(String, String)]) -> Result<(), String>`
- `drop_table(conn, table_name) -> Result<(), String>`
- `add_column(conn, table_name, col_name, col_type) -> Result<(), String>`
- `drop_column(conn, table_name, col_name) -> Result<(), String>`

Unit tests:
- `test_create_and_drop_table` - create table, verify in sqlite_master, drop, verify gone
- `test_add_and_drop_column` - add column, verify pragma_table_info count, drop, verify
- `test_validate_identifier_rejects_sql_injection` - semicolons, empty, numeric start
- `test_validate_identifier_rejects_reserved_words` - "select", "table"
- `test_invalid_column_type_rejected` - "VARCHAR(255)" rejected

**Step 3: Run all tests**

Run: `cargo test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/db/schema.rs src/db/mod.rs
git commit -m "feat: SQLite DDL operations with SQL injection prevention"
```

---

### Task CRUISE-005: Askama Templates and htmx Static Assets

**Files:**
- Create: `templates/base.html`
- Create: `templates/login.html`
- Create: `templates/dashboard.html`
- Create: `templates/table_list.html`
- Create: `templates/table_detail.html`
- Create: `static/htmx.min.js`
- Modify: `Cargo.toml` (add askama, askama_axum)

**Step 1: Add template dependencies**

```toml
askama = "0.12"
askama_axum = "0.4"
```

**Step 2: Download htmx**

Run: `mkdir -p static && curl -o static/htmx.min.js https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js`

**Step 3: Create base template** - HTML layout with htmx script, basic CSS, nav structure. Include a `<meta name="csrf-token" content="{{ csrf_token }}">` tag and a script block that configures htmx to attach the CSRF token to all requests via `document.body.addEventListener("htmx:configRequest", function(evt) { evt.detail.headers["X-CSRF-Token"] = document.querySelector('meta[name="csrf-token"]').content; });`.

**Step 4: Create login template** - Extends base, token input form, optional error message.

**Step 5: Create dashboard template** - Extends base, shows logged-in user, `hx-get="/tables"` container.

**Step 6: Create table_list.html partial** - htmx partial: create table form (`hx-post="/tables"`), table list with delete buttons (`hx-delete` with `hx-confirm`), links to table detail (`hx-get="/tables/{name}"`).

**Step 7: Create table_detail.html partial** - htmx partial: add column form (`hx-post`), column list with drop buttons (`hx-delete` with `hx-confirm`).

**Step 8: Commit**

```bash
git add templates/ static/ Cargo.toml Cargo.lock
git commit -m "feat: Askama templates and htmx static assets"
```

---

### Task CRUISE-006a: Auth Handlers, Config, and Router Setup

**Files:**
- Create: `src/handlers/mod.rs`
- Create: `src/handlers/auth.rs`
- Create: `src/config.rs`
- Modify: `src/main.rs` (initial router wiring with auth routes, static serving, CSRF infrastructure)
- Modify: `Cargo.toml` (add tower-http, cookie)

**Step 1: Add dependencies**

```toml
tower-http = { version = "0.6", features = ["fs"] }
```

**Step 2: Create config.rs** - Read PORT, DB_PATH, PUBLIC_KEY_PATH, PRIVATE_KEY_PATH from env vars with defaults.

**Step 3: Create auth handlers**

`src/handlers/auth.rs`:
- `login_page()` - renders login.html template
- `login_submit(Form<LoginForm>)` - validates JWT, sets Secure HttpOnly SameSite=Strict cookie, generates a per-session CSRF token (random 32-byte hex string stored server-side keyed to the session), sets it as a second cookie or embeds it in the redirect response, redirects to /
- `logout()` - clears cookie and CSRF token, redirects to /login
- `dashboard(Request)` - extracts Claims from extensions, renders dashboard.html with CSRF token embedded in a `<meta name="csrf-token">` tag for htmx to read

**Step 4: Create handlers/mod.rs**

```rust
pub mod auth;
```

**Step 5: Wire initial main.rs with auth routes and CSRF infrastructure**

Routes wired in this task:
- Protected (behind auth middleware): `GET /` (dashboard)
- Public: `GET /login`, `POST /login`, `GET /logout`, `GET /healthz`, `GET /.well-known/jwks.json`
- Static: `GET /static/*` via ServeDir

CSRF validation middleware: For POST, PUT, DELETE requests on protected routes, extract the `X-CSRF-Token` header and validate it against the server-side session token. Return 403 Forbidden if the token is missing or invalid. Store CSRF tokens in a concurrent HashMap keyed by session/user identifier.

Note: Table and column routes are wired in CRUISE-006b. The router is structured so that CRUISE-006b can add its routes to the existing protected router group.

**Step 6: Build and verify**

Run: `cargo build`
Expected: Compiles successfully

**Step 7: Commit**

```bash
git add src/handlers/mod.rs src/handlers/auth.rs src/config.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat: auth handlers, config, CSRF infrastructure, and initial router wiring"
```

---

### Task CRUISE-006b: Table/Column Handlers and Full Router Wiring

**Files:**
- Create: `src/handlers/tables.rs`
- Create: `src/handlers/columns.rs`
- Modify: `src/handlers/mod.rs` (add tables, columns modules)
- Modify: `src/main.rs` (add table/column routes to protected router group)

**Step 1: Create table handlers**

`src/handlers/tables.rs`:
- `list_tables()` - renders table_list.html partial
- `create_table(Form)` - calls schema::create_table, re-renders table list
- `delete_table(Path)` - calls schema::drop_table, re-renders table list
- `show_table(Path)` - renders table_detail.html partial

**Step 2: Create column handlers**

`src/handlers/columns.rs`:
- `add_column(Path, Form)` - calls schema::add_column, re-renders table detail
- `drop_column(Path)` - calls schema::drop_column, re-renders table detail

**Step 3: Update handlers/mod.rs**

```rust
pub mod auth;
pub mod tables;
pub mod columns;
```

**Step 4: Wire table/column routes into main.rs**

Add to the existing protected router group:
- `GET /tables`, `POST /tables`, `DELETE /tables/{name}`, `GET /tables/{name}`, `POST /tables/{name}/columns`, `DELETE /tables/{name}/columns/{col}`

All these routes are behind the auth middleware and CSRF validation middleware established in CRUISE-006a.

**Step 5: Build and verify**

Run: `cargo build`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add src/handlers/ src/main.rs
git commit -m "feat: table and column handlers with full router wiring"
```

---

### Task CRUISE-007: Playwright E2E Test Infrastructure

**Files:**
- Create: `tests/e2e/package.json`
- Create: `tests/e2e/playwright.config.ts`
- Create: `tests/e2e/tsconfig.json`
- Create: `tests/e2e/helpers/jwt.ts`
- Create: `scripts/run-e2e.sh`

**Step 1: Create package.json**

```json
{
  "name": "sqlite-editor-e2e",
  "private": true,
  "scripts": {
    "test": "playwright test",
    "test:headed": "playwright test --headed"
  },
  "devDependencies": {
    "@playwright/test": "^1.50.0",
    "jsonwebtoken": "^9.0.0"
  }
}
```

**Step 2: Create playwright.config.ts**

- testDir: `./specs`
- baseURL: `http://localhost:3000`
- webServer: `cd ../.. && cargo run` on port 3000 with 120s timeout
- Reporters: list, html (playwright-report/), json (test-results/results.json)

**Step 3: Create JWT test helper** (`tests/e2e/helpers/jwt.ts`)

- `generateToken(sub, expiresInSeconds)` - signs JWT with RS256 using private key
- `generateExpiredToken(sub)` - creates already-expired token
- `ensureKeys()` - runs generate-keys.sh if keys and certificate don't exist

Note: Uses `child_process.execFileSync` (not `execSync`) for safety - only runs the key generation script with hardcoded paths, no user input.

**Step 4: Create run-e2e.sh** - generates keys and certificate, installs npm deps, installs Playwright chromium, runs tests.

**Step 5: Install and verify**

Run: `cd tests/e2e && npm install && npx playwright install chromium`

**Step 6: Commit**

```bash
git add tests/e2e/ scripts/
git commit -m "feat: Playwright E2E test infrastructure with JWT helper"
```

---

### Task CRUISE-008: E2E Test Specs

**Files:**
- Create: `tests/e2e/specs/auth.spec.ts`
- Create: `tests/e2e/specs/tables.spec.ts`
- Create: `tests/e2e/specs/columns.spec.ts`

**Step 1: Write auth.spec.ts**

Tests:
- `should show login page when not authenticated` - GET / shows token input
- `should login with valid JWT token` - 5-minute token, verify dashboard shows username
- `should reject expired JWT token` - expired token shows error message
- `should reject invalid JWT token` - garbage string shows error
- `should logout successfully` - login, click logout, verify login page shown
- `.well-known/jwks.json returns valid JWKS` - API request, verify kty/alg/n/e fields

**Step 2: Write tables.spec.ts**

Tests (each test logs in with fresh JWT first):
- `should create a new table` - fill form, submit, verify table appears in list
- `should delete a table` - create table, accept confirm dialog, click delete, verify gone
- `should show table details when clicking table name` - create table, click name, verify detail view

**Step 3: Write columns.spec.ts**

Tests (each test logs in and creates a table first):
- `should add a column to a table` - fill column form, submit, verify column appears
- `should drop a column from a table` - add column, accept confirm, click drop, verify gone
- `should show correct column types` - add TEXT, INTEGER, REAL columns, verify types shown

**Step 4: Run tests**

Run: `cd tests/e2e && npx playwright test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add tests/e2e/specs/
git commit -m "feat: E2E test specs for auth, tables, and columns"
```

---

### Task CRUISE-009: GitHub Actions - Lint Workflow

**Files:**
- Create: `.github/workflows/lint.yml`

**Step 1: Create lint workflow**

```yaml
name: Lint

on:
  pull_request:
    branches: ["*"]

permissions:
  contents: read
  packages: read
  statuses: write

jobs:
  lint:
    name: Super-Linter
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Super-Linter
        uses: super-linter/super-linter@v7
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VALIDATE_ALL_CODEBASE: false
          DEFAULT_BRANCH: main
          VALIDATE_RUST_2021: true
          VALIDATE_RUST_CLIPPY: true
          VALIDATE_TYPESCRIPT_ES: true
          VALIDATE_YAML: true
          VALIDATE_HTML: true
          VALIDATE_BASH: true
          VALIDATE_SHELL_SHFMT: true
```

**Step 2: Commit**

```bash
git add .github/workflows/lint.yml
git commit -m "ci: add Super-Linter workflow for PRs"
```

---

### Task CRUISE-010: GitHub Actions - Dependency Review Workflow

**Files:**
- Create: `.github/workflows/dependency-review.yml`

**Step 1: Create dependency review workflow**

```yaml
name: Dependency Review

on:
  pull_request:
    branches: ["*"]

permissions:
  contents: read

jobs:
  dependency-review:
    name: Dependency Review
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: moderate
```

**Step 2: Commit**

```bash
git add .github/workflows/dependency-review.yml
git commit -m "ci: add dependency review workflow for PRs"
```

---

### Task CRUISE-011: GitHub Actions - E2E Test Workflow

**Files:**
- Create: `.github/workflows/e2e.yml`

**Step 1: Create E2E test workflow**

```yaml
name: E2E Tests

on:
  pull_request:
    branches: ["*"]

permissions:
  contents: read

jobs:
  e2e:
    name: Playwright E2E Tests
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Cache Rust dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Build Rust server
        run: cargo build --release

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install test dependencies
        working-directory: tests/e2e
        run: npm ci

      - name: Install Playwright browsers
        working-directory: tests/e2e
        run: npx playwright install --with-deps chromium

      - name: Generate JWT keys
        run: bash scripts/generate-keys.sh

      - name: Run E2E tests
        working-directory: tests/e2e
        run: npx playwright test
        env:
          CI: true

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report
          path: tests/e2e/playwright-report/
          retention-days: 30

      - name: Upload test results JSON
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: tests/e2e/test-results/
          retention-days: 30

      - name: Publish test results to PR
        if: always() && github.event_name == 'pull_request'
        uses: daun/playwright-report-summary@v3
        with:
          report-file: tests/e2e/test-results/.last-run.json
          comment-title: 'Playwright E2E Test Results'
```

> **Note on "push test results to the repository":** Test results are surfaced on the PR via two mechanisms: (1) GitHub Actions artifacts store the full Playwright report and raw results for download/debugging, and (2) a PR comment summary (via `playwright-report-summary` action) posts pass/fail results directly on the PR for immediate visibility. Results are NOT committed to the repository branch, as committing generated test output would pollute the git history and is not standard CI practice. Artifacts + PR comments provide equivalent validation visibility without repository pollution.

**Step 2: Commit**

```bash
git add .github/workflows/e2e.yml
git commit -m "ci: add Playwright E2E test workflow with artifact upload"
```

---

### Task CRUISE-012: Integration Testing and Final Verification

**Files:**
- Modify: various files as needed for bug fixes

**Step 1: Generate keys and build**

```bash
bash scripts/generate-keys.sh
cargo build
```
Expected: Successful build

**Step 2: Verify endpoints**

```bash
cargo run &
sleep 2
curl http://localhost:3000/healthz          # expect: "ok"
curl http://localhost:3000/.well-known/jwks.json  # expect: valid JWKS JSON
kill %1
```

**Step 3: Run unit tests**

Run: `cargo test`
Expected: All tests pass

**Step 4: Run E2E tests**

Run: `cd tests/e2e && npx playwright test`
Expected: All E2E tests pass

**Step 5: Fix any issues, re-run**

**Step 6: Final commit**

```bash
git add -A
git commit -m "fix: integration fixes from full E2E verification"
```

---

## Task Dependency Graph

```
CRUISE-001 (Scaffolding + .gitignore)
    ├── CRUISE-002 (JWT + JWKS)
    │       └── CRUISE-003 (Auth Middleware)
    ├── CRUISE-004a (SQLite Connection + Queries)
    │       └── CRUISE-004b (SQLite DDL Operations)
    ├── CRUISE-005 (Templates + htmx)
    ├── CRUISE-007 (E2E Test Setup)
    ├── CRUISE-009 (Lint CI)
    └── CRUISE-010 (Dep Review CI)

CRUISE-006a (Auth Handlers + Router Setup) ← depends on 002, 003, 005
CRUISE-006b (Table/Column Handlers) ← depends on 004b, 005, 006a
CRUISE-008 (E2E Test Specs) ← depends on 006b, 007
CRUISE-011 (E2E CI) ← depends on 007, 008
CRUISE-012 (Integration) ← depends on all above
```

**Parallelization opportunities after CRUISE-001:**
- CRUISE-002+003, CRUISE-004a, CRUISE-005, CRUISE-007, CRUISE-009, CRUISE-010 can all run in parallel.
- CRUISE-004b can start as soon as CRUISE-004a completes, allowing focused security review of DDL operations and identifier validation separately from connection/query logic.
- CRUISE-006a can start as soon as 002, 003, and 005 are complete — without waiting for the Database Layer (004a/004b). This reduces the critical path by allowing auth handler development to proceed in parallel with database layer work.

---

```json
{
  "title": "SQLite Database Editor Web Application",
  "overview": "Rust web app with Axum backend, htmx frontend, JWT auth (RS256 with JWKS endpoint), SQLite schema management (create/drop tables, add/drop columns), Playwright E2E tests, and GitHub Actions CI/CD (super-linter + dependency review).",
  "spawn_instances": [
    {
      "id": "SPAWN-001",
      "name": "Project Foundation",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-001"]
    },
    {
      "id": "SPAWN-002",
      "name": "Authentication System",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-002", "CRUISE-003"]
    },
    {
      "id": "SPAWN-003",
      "name": "Database Layer",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-004a", "CRUISE-004b"]
    },
    {
      "id": "SPAWN-004",
      "name": "Frontend Templates",
      "use_spawn_team": false,
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit,Bash,Glob --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob"],
      "task_ids": ["CRUISE-005"]
    },
    {
      "id": "SPAWN-005",
      "name": "Application Wiring",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-006a", "CRUISE-006b"]
    },
    {
      "id": "SPAWN-006",
      "name": "E2E Test Infrastructure and Specs",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-007", "CRUISE-008"]
    },
    {
      "id": "SPAWN-007",
      "name": "CI/CD Workflows",
      "use_spawn_team": false,
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "permissions": ["Read", "Write", "Edit"],
      "task_ids": ["CRUISE-009", "CRUISE-010", "CRUISE-011"]
    },
    {
      "id": "SPAWN-008",
      "name": "Integration and Verification",
      "use_spawn_team": true,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 900",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-012"]
    }
  ],
  "tasks": [
    {
      "id": "CRUISE-001",
      "subject": "Project Scaffolding and .gitignore",
      "description": "Create comprehensive .gitignore (keys, credentials, temp files, build artifacts, node_modules, editor/IDE files, OS files for mac/windows/linux, .env, logs, .fork-join), minimal Cargo.toml with axum+tokio, and hello-world main.rs with /healthz endpoint. Verify it compiles.",
      "blocked_by": [],
      "complexity": "low",
      "acceptance_criteria": [
        ".gitignore covers: *.pem, *.key, *.crt, .env, *.db, *.sqlite, node_modules/, target/, .DS_Store, Thumbs.db, Desktop.ini, .vscode/, .idea/, *.log, .fork-join/, editor swap files, OS files for mac/windows/linux",
        "Cargo.toml has axum and tokio dependencies",
        "src/main.rs has /healthz endpoint returning 'ok'",
        "cargo build succeeds"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-001"
    },
    {
      "id": "CRUISE-002",
      "subject": "JWT Key Generation and JWKS Endpoint",
      "description": "Create RSA key generation script (scripts/generate-keys.sh using openssl) that generates a private key, public key, and self-signed X.509 certificate (local JWT CA). Create JWT validation module (src/auth/jwt.rs with RS256 support), and JWKS endpoint handler (src/auth/jwks.rs) that serves public key at /.well-known/jwks.json. Use the `rsa` crate to parse PEM and extract JWKS components (modulus, exponent) at server startup, pre-computing the JWKS response. Add jsonwebtoken, serde, serde_json, base64, rsa, chrono crate dependencies. Include unit tests for token validation (valid token, expired token).",
      "blocked_by": ["CRUISE-001"],
      "complexity": "high",
      "acceptance_criteria": [
        "scripts/generate-keys.sh generates RSA 2048-bit key pair and self-signed X.509 certificate",
        "JWT validation works with RS256 algorithm",
        "Unit test: valid token accepted",
        "Unit test: expired token rejected",
        "/.well-known/jwks.json returns valid JWK Set with RSA public key",
        "Private keys excluded by .gitignore"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-002"
    },
    {
      "id": "CRUISE-003",
      "subject": "JWT Auth Middleware",
      "description": "Create Axum middleware (src/auth/middleware.rs) that extracts JWT from Authorization Bearer header or cookie, validates it, and injects Claims into request extensions. Unauthenticated requests return 401.",
      "blocked_by": ["CRUISE-002"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Middleware extracts token from Authorization: Bearer header",
        "Middleware extracts token from cookie named 'token'",
        "Valid token: Claims injected into request extensions",
        "Invalid/missing token: 401 Unauthorized returned",
        "Code compiles successfully"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-002"
    },
    {
      "id": "CRUISE-004a",
      "subject": "SQLite Connection and Query Helpers",
      "description": "Create database connection pool (src/db/connection.rs with Mutex<Connection>) and query helpers (src/db/queries.rs: list_tables, describe_table). Add rusqlite with bundled feature for SQLite 3.35+ (DROP COLUMN support). Include unit tests for connection and query operations.",
      "blocked_by": ["CRUISE-001"],
      "complexity": "medium",
      "acceptance_criteria": [
        "rusqlite with bundled feature in Cargo.toml",
        "DbPool wraps Mutex<Connection> with safe with_conn access method",
        "list_tables returns all user tables (excludes sqlite_* internal tables)",
        "describe_table returns column info (name, type, notnull, pk)",
        "Unit tests pass for connection pool and query helpers"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-003"
    },
    {
      "id": "CRUISE-004b",
      "subject": "SQLite DDL Operations with Identifier Validation",
      "description": "Create DDL operations (src/db/schema.rs: create_table, drop_table, add_column, drop_column) with identifier validation to prevent SQL injection. This is security-sensitive code requiring careful validation of all user-provided identifiers and column types. Include comprehensive unit tests covering both valid operations and injection attempts.",
      "blocked_by": ["CRUISE-004a"],
      "complexity": "high",
      "acceptance_criteria": [
        "validate_identifier prevents SQL injection (alphanumeric + underscore only, rejects reserved words)",
        "validate_column_type whitelists only TEXT, INTEGER, REAL, BLOB, NUMERIC",
        "create_table and drop_table work correctly",
        "add_column and drop_column work correctly",
        "Unit tests pass for all DDL operations",
        "Unit tests cover SQL injection attempts (semicolons, empty, numeric start, reserved words)",
        "Unit test: invalid column type like VARCHAR(255) rejected"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-003"
    },
    {
      "id": "CRUISE-005",
      "subject": "Askama Templates and htmx Static Assets",
      "description": "Create Askama HTML templates: base.html (layout with htmx script), login.html (token input form), dashboard.html (nav + table list container), table_list.html (htmx partial with create/delete), table_detail.html (htmx partial with add/drop columns). Download htmx.min.js to static/. Add askama and askama_axum dependencies.",
      "blocked_by": ["CRUISE-001"],
      "complexity": "medium",
      "acceptance_criteria": [
        "All templates use Askama syntax and extend base.html",
        "htmx attributes used for dynamic table/column CRUD (hx-get, hx-post, hx-delete, hx-target, hx-swap, hx-confirm)",
        "Login form accepts JWT token input",
        "Dashboard shows logged-in user and table list",
        "Table list has create and delete actions",
        "Table detail has add column and drop column actions",
        "htmx.min.js present in static/"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit,Bash,Glob --timeout 300",
      "spawn_instance": "SPAWN-004"
    },
    {
      "id": "CRUISE-006a",
      "subject": "Auth Handlers, Config, and Router Setup",
      "description": "Create auth HTTP handlers (login page, login POST with cookie and CSRF token, logout, dashboard), config.rs for env-based configuration, and initial main.rs router wiring: protected dashboard route behind auth middleware, public routes (login, JWKS, health), static file serving via tower-http ServeDir, and CSRF validation middleware infrastructure. Add tower-http dependency.",
      "blocked_by": ["CRUISE-002", "CRUISE-003", "CRUISE-005"],
      "complexity": "high",
      "acceptance_criteria": [
        "Login page renders at GET /login",
        "POST /login validates JWT, sets Secure HttpOnly SameSite=Strict cookie, and generates a per-session CSRF token",
        "GET /logout clears cookie and redirects to /login",
        "GET / shows dashboard (protected)",
        "GET /static/* serves static files",
        "CSRF token generated per session and validated on all state-changing (POST/PUT/DELETE) protected endpoints via X-CSRF-Token header",
        "CSRF token embedded in base template via meta tag and attached to htmx requests via htmx:configRequest event listener",
        "Missing or invalid CSRF token returns 403 Forbidden",
        "Router is structured so table/column routes can be added in CRUISE-006b",
        "cargo build succeeds"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-005"
    },
    {
      "id": "CRUISE-006b",
      "subject": "Table/Column Handlers and Full Router Wiring",
      "description": "Create table handlers (list, create, delete, show detail) and column handlers (add, drop). Wire table/column routes into the existing protected router group established in CRUISE-006a. All routes are behind auth middleware and CSRF validation.",
      "blocked_by": ["CRUISE-004b", "CRUISE-005", "CRUISE-006a"],
      "complexity": "medium",
      "acceptance_criteria": [
        "GET /tables returns table list partial (protected)",
        "POST /tables creates table (protected)",
        "DELETE /tables/{name} drops table (protected)",
        "GET /tables/{name} returns table detail partial (protected)",
        "POST /tables/{name}/columns adds column (protected)",
        "DELETE /tables/{name}/columns/{col} drops column (protected)",
        "cargo build succeeds"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-005"
    },
    {
      "id": "CRUISE-007",
      "subject": "Playwright E2E Test Infrastructure",
      "description": "Create tests/e2e/ with package.json (playwright + jsonwebtoken deps), playwright.config.ts (webServer pointing to cargo run, JSON and HTML reporters), tsconfig.json, JWT test helper (generates valid/expired RS256 tokens using private key via execFileSync), and run-e2e.sh script that generates keys and certificate, installs deps, runs tests.",
      "blocked_by": ["CRUISE-001"],
      "complexity": "medium",
      "acceptance_criteria": [
        "package.json has @playwright/test and jsonwebtoken dependencies",
        "playwright.config.ts configures webServer to start Rust server with 120s timeout",
        "JSON reporter outputs to test-results/results.json",
        "JWT helper generates valid RS256 tokens with configurable expiry",
        "JWT helper generates expired tokens for negative testing",
        "run-e2e.sh generates keys and certificate, installs deps, runs tests",
        "npm install succeeds in tests/e2e/"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-006"
    },
    {
      "id": "CRUISE-008",
      "subject": "E2E Test Specs",
      "description": "Write Playwright test specs: auth.spec.ts (login with valid JWT, reject expired JWT, reject invalid JWT, logout, JWKS endpoint), tables.spec.ts (create table, delete table, view table details), columns.spec.ts (add column, drop column, verify column types). All tests use short-lived (5-min) JWT tokens.",
      "blocked_by": ["CRUISE-006b", "CRUISE-007"],
      "complexity": "high",
      "acceptance_criteria": [
        "Auth tests: valid login, expired token rejection, invalid token rejection, logout, JWKS endpoint validation",
        "Table tests: create table, delete table with confirmation dialog, view table detail",
        "Column tests: add column, drop column with confirmation dialog, verify TEXT/INTEGER/REAL column types",
        "All tests use programmatically-generated short-lived (300s) JWT tokens",
        "All tests pass when run against the application"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "spawn_instance": "SPAWN-006"
    },
    {
      "id": "CRUISE-009",
      "subject": "GitHub Actions Lint Workflow",
      "description": "Create .github/workflows/lint.yml using super-linter/super-linter@v7. Triggered on all PRs. Validates Rust (clippy), TypeScript, YAML, HTML, and shell scripts. Only validates changed files (VALIDATE_ALL_CODEBASE: false).",
      "blocked_by": ["CRUISE-001"],
      "complexity": "low",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to any branch",
        "Uses super-linter/super-linter@v7",
        "VALIDATE_ALL_CODEBASE set to false",
        "Validates: Rust clippy, TypeScript, YAML, HTML, Bash",
        "Correct permissions set (contents: read, packages: read, statuses: write)"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-010",
      "subject": "GitHub Actions Dependency Review Workflow",
      "description": "Create .github/workflows/dependency-review.yml using actions/dependency-review-action@v4. Triggered on all PRs. Fails on moderate+ severity vulnerabilities.",
      "blocked_by": ["CRUISE-001"],
      "complexity": "low",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to any branch",
        "Uses actions/dependency-review-action@v4",
        "fail-on-severity set to moderate",
        "Correct permissions (contents: read)"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-011",
      "subject": "GitHub Actions E2E Test Workflow",
      "description": "Create .github/workflows/e2e.yml that builds Rust server, installs Node.js + Playwright, generates JWT keys, runs E2E tests, uploads test results (playwright-report/ and test-results/) as artifacts with 30-day retention, and posts a test result summary as a PR comment for direct visibility. Triggered on all PRs. Caches Cargo dependencies.",
      "blocked_by": ["CRUISE-007", "CRUISE-008"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to any branch",
        "Installs Rust stable toolchain and caches cargo dependencies",
        "Builds Rust server in release mode",
        "Sets up Node.js 20 and installs test dependencies with npm ci",
        "Generates JWT keys before running tests",
        "Runs Playwright tests with CI=true",
        "Uploads playwright-report and test-results as artifacts (always, even on failure)",
        "Artifact retention set to 30 days",
        "Posts test result summary as a PR comment via playwright-report-summary action for direct PR visibility (results are NOT committed to the branch; artifacts + PR comments satisfy the validation requirement without polluting git history)"
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-012",
      "subject": "Integration Testing and Final Verification",
      "description": "End-to-end verification: generate keys, build server, verify healthz and JWKS endpoints manually via curl, run cargo test (all unit tests), run Playwright E2E tests. Fix any issues found. Ensure no compiler warnings. Final commit.",
      "blocked_by": ["CRUISE-001", "CRUISE-002", "CRUISE-003", "CRUISE-004a", "CRUISE-004b", "CRUISE-005", "CRUISE-006a", "CRUISE-006b", "CRUISE-007", "CRUISE-008", "CRUISE-009", "CRUISE-010", "CRUISE-011"],
      "complexity": "medium",
      "acceptance_criteria": [
        "cargo build succeeds with no warnings",
        "cargo test passes all unit tests",
        "/healthz returns 'ok'",
        "/.well-known/jwks.json returns valid JWKS with RSA key",
        "All Playwright E2E tests pass (auth, tables, columns)",
        "All code committed and clean git status"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 900",
      "spawn_instance": "SPAWN-008"
    }
  ],
  "risks": [
    "rusqlite synchronous calls must be wrapped in spawn_blocking for Axum async handlers - forgetting this will block the tokio runtime",
    "SQLite ALTER TABLE DROP COLUMN requires SQLite 3.35+ - must use rusqlite 'bundled' feature to guarantee this",
    "SQL injection via dynamically-constructed DDL statements - table/column names must be strictly validated (no quoting, only alphanumeric + underscore)",
    "JWT private key and certificate leakage - .gitignore must exclude *.pem, *.key; tests generate ephemeral keys and certificates",
    "Playwright test flakiness from server startup race condition - playwright.config.ts webServer config handles this but timeout must be sufficient for Rust compilation in CI (120s)",
    "htmx CSRF vulnerability - hx-* requests bypass traditional form CSRF tokens; SameSite=Strict cookies alone are insufficient for destructive DDL operations. Mitigated by generating per-session CSRF tokens, embedding them in templates via meta tags, and configuring htmx to send them as X-CSRF-Token headers on every request. Server validates the token on all state-changing endpoints (POST/PUT/DELETE)",
    "Super-linter may have different Rust edition expectations - need to configure RUST_EDITION or accept some false positives",
    "Askama template compile-time errors will fail the entire build - templates must be syntactically correct before integration",
    "CI build times may be slow due to Rust compilation - cargo cache action is critical for acceptable CI performance",
    "openssl dependency for key and certificate generation scripts only (not runtime JWKS parsing or tests) - must be available in CI runner (ubuntu-latest includes it). JWKS parsing uses the `rsa` crate at startup; tests use `rsa` + `rand` crates for ephemeral keypair generation."
  ]
}
```
