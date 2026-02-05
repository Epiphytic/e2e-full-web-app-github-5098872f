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
4. **htmx CSRF**: htmx sends AJAX requests that bypass traditional form-based CSRF protections. **Secure HttpOnly SameSite=Strict cookies are a defense-in-depth measure only and are NOT sufficient as the sole CSRF protection**, especially for a database editor performing destructive DDL operations (DROP TABLE, DROP COLUMN). The **primary** CSRF defense is explicit per-session CSRF tokens: generate a cryptographically random 32-byte token server-side per session, embed it in every page via a `<meta name="csrf-token">` tag, and configure htmx globally to attach it to all requests using either `hx-headers='{"X-CSRF-Token": "..."}'` on the `<body>` element or `document.body.addEventListener("htmx:configRequest", ...)`. The server MUST validate the `X-CSRF-Token` header on all state-changing endpoints (POST, PUT, DELETE) and return 403 Forbidden if the token is missing or invalid. The session cookie must be set with `Secure` (HTTPS-only transmission), `HttpOnly` (no JavaScript access), and `SameSite=Strict` flags as an additional defense layer, but these must not be relied upon alone.
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
- Modify: `Cargo.toml` (add jsonwebtoken, serde, serde_json, base64, rsa, chrono, x509-cert, pem; add rand and rcgen as dev-dependencies for test keypair and certificate generation)
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

The `x509-cert` and `pem` crates are required to extract the RSA public key from the self-signed X.509 certificate (`cert.pem`) at server startup. The extraction happens once and the result is cached in application state — no certificate parsing occurs on the request path. The `rcgen` dev-dependency generates ephemeral certificates for unit tests.

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
x509-cert = { version = "0.2", features = ["pem"] }  # Parse X.509 certificate from local JWT CA
pem = "3"                                             # PEM encoding/decoding for certificate handling

[dev-dependencies]
rand = "0.8"
rcgen = "0.13"  # Generate ephemeral self-signed certificates in tests
```

Note: The `generate-keys.sh` script (Step 1) produces three artifacts: `private.pem` (RSA private key), `public.pem` (RSA public key), and `cert.pem` (self-signed X.509 certificate). The certificate satisfies the local JWT CA requirement — at server startup, the public key is extracted from `cert.pem` once using the `x509-cert` crate and cached in application state for efficient per-request token validation.

**Step 4: Write JWT validation module with tests**

Create `src/auth/jwt.rs`. This module supports two modes of key loading: a raw RSA public key PEM (`public.pem`) and an X.509 certificate PEM (`cert.pem`) from the local JWT CA. The `extract_public_key_from_cert` function extracts the public key from the certificate **once at server startup** (not per-request), and the extracted PEM is then stored in application state for reuse. This avoids any per-request certificate parsing overhead:

```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

/// Validate a JWT using a raw RSA public key PEM
pub fn validate_token(token: &str, public_key_pem: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key_pem)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

/// Extract the RSA public key PEM from an X.509 certificate PEM using the `x509-cert` crate.
/// This MUST be called once at server startup, and the result cached in application state.
/// The middleware then calls `validate_token` with the pre-extracted public key PEM —
/// no certificate parsing occurs on the request path.
pub fn extract_public_key_from_cert(cert_pem: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use x509_cert::der::Decode;
    let pem_str = std::str::from_utf8(cert_pem)?;
    let (_, doc) = x509_cert::der::pem::PemDocument::from_pem(pem_str)?;
    let cert = x509_cert::Certificate::from_der(doc.as_bytes())?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    let public_key_der = spki.to_der()?;
    let public_key_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", public_key_der));
    Ok(public_key_pem.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;
    use rcgen::{CertificateParams, KeyPair};

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

    /// Generate a test keypair along with a self-signed X.509 certificate
    fn generate_test_keypair_with_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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

        // Generate self-signed X.509 certificate using rcgen
        let key_pair = KeyPair::from_pem(&String::from_utf8(private_pem.clone()).unwrap())
            .expect("failed to create key pair");
        let mut params = CertificateParams::new(vec!["LocalJWTCA".to_string()])
            .expect("failed to create cert params");
        params.distinguished_name.push(rcgen::DnType::CommonName, "LocalJWTCA");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Development");
        let cert = params.self_signed(&key_pair).expect("failed to generate self-signed certificate");
        let cert_pem = cert.pem().into_bytes();

        (private_pem, public_pem, cert_pem)
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
    fn test_validate_token_with_certificate() {
        let (private_pem, _public_pem, cert_pem) = generate_test_keypair_with_cert();
        let claims = Claims {
            sub: "testuser".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };
        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(&private_pem).unwrap();
        let token = encode(&header, &claims, &key).unwrap();

        // Extract public key from cert once (simulating startup), then validate with extracted key
        let extracted_pem = extract_public_key_from_cert(&cert_pem).unwrap();
        let result = validate_token(&token, &extracted_pem);
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
Expected: 3 tests pass (valid token, certificate-based validation, expired token rejection)

**Step 6: Create JWKS endpoint handler**

Create `src/auth/jwks.rs` - uses the `rsa` crate to parse the RSA public key PEM and extract modulus (n) and exponent (e) components **at server startup**. The pre-computed JWKS JSON is cached as shared application state so the handler simply returns it without any per-request parsing. This avoids shelling out to any CLI tool (e.g., `openssl`) at runtime.

```rust
use axum::{extract::State, http::StatusCode, response::Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde_json::{json, Value};
use std::sync::Arc;

/// Pre-computed JWKS response, built once at startup
#[derive(Clone)]
pub struct JwksState {
    pub jwks_json: Arc<Value>,
}

/// Build the JWKS JSON from a PEM-encoded RSA public key at startup.
/// Uses the `rsa` crate to parse the PEM and extract modulus/exponent —
/// no CLI tools or subprocess calls are involved.
pub fn build_jwks_from_pem(public_key_pem: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let pem_str = std::str::from_utf8(public_key_pem)?;
    let public_key = RsaPublicKey::from_public_key_pem(pem_str)?;

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    let n_b64 = URL_SAFE_NO_PAD.encode(&n);
    let e_b64 = URL_SAFE_NO_PAD.encode(&e);

    Ok(json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": n_b64,
            "e": e_b64
        }]
    }))
}

/// Handler returns the pre-computed JWKS JSON (no per-request computation)
pub async fn jwks_handler(
    State(state): State<JwksState>,
) -> Result<Json<Value>, StatusCode> {
    Ok(Json((*state.jwks_json).clone()))
}
```

**Step 7: Create auth/mod.rs**

```rust
pub mod jwt;
pub mod jwks;
pub mod middleware;
```

**Step 8: Wire JWKS into main.rs**

At startup: (1) call `auth::jwt::extract_public_key_from_cert(&cert_pem)` to extract the RSA public key PEM from the X.509 certificate once, then store the extracted PEM in `AuthState` for use by the auth middleware; (2) call `auth::jwks::build_jwks_from_pem(&public_pem)` to pre-compute the JWKS JSON using the `rsa` crate and store the result in `JwksState`. Both operations happen once at startup — no certificate or key parsing occurs on the request path. Add `/.well-known/jwks.json` route pointing to `auth::jwks::jwks_handler`, which simply returns the cached response with zero per-request overhead. Note: when the authentication cookie is set later (in CRUISE-006a), it must include the `Secure` flag (HTTPS-only transmission) in addition to `HttpOnly` and `SameSite=Strict` to ensure the token is never sent over plaintext connections. **Important:** these cookie attributes are defense-in-depth only — they are NOT sufficient as the sole CSRF protection for destructive DDL operations. The primary CSRF defense (explicit per-session CSRF tokens validated via `X-CSRF-Token` header on all state-changing endpoints) is implemented in CRUISE-006a.

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

**Note:** This middleware handles authentication (identity verification) only. CSRF protection is a separate concern implemented in CRUISE-006a via explicit per-session CSRF tokens validated on all state-changing endpoints (POST/PUT/DELETE) through the `X-CSRF-Token` header. The `Secure`, `HttpOnly`, and `SameSite=Strict` cookie attributes set on the JWT session cookie are defense-in-depth only and must NOT be relied upon as the sole CSRF protection, especially given this application performs destructive DDL operations (DROP TABLE, DROP COLUMN). See CRUISE-006a Step 5 for the full CSRF validation middleware specification.

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

> **Split rationale:** Originally a single CRUISE-004 task covering connection pooling, DDL operations, and query helpers. Reviewers noted that this was too large and that splitting DDL operations from basic connection/query logic would enable better parallel execution and focused security review. The task is now split into 004a (connection pool + read-only queries) and 004b (DDL operations + identifier validation). This separation provides three key benefits: (1) **parallel execution** — 004a and other tasks can proceed independently while 004b receives focused implementation attention, and the two subtasks are assigned to separate spawn instances (SPAWN-003a and SPAWN-003b) for concurrent development, (2) **security boundary** — 004a has zero SQL injection surface since it only reads schema metadata via SQLite PRAGMAs, while 004b dynamically constructs DDL from user-provided identifiers, requiring strict validation (alphanumeric + underscore only, reserved word rejection, column type whitelisting) — isolating this code enables a dedicated security review of the injection prevention logic, and (3) **independent review** — the security-sensitive DDL code in 004b can be reviewed without being interleaved with connection pool boilerplate, reducing reviewer cognitive load and ensuring injection prevention logic gets the scrutiny it deserves.

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

> **Split rationale:** Separated from CRUISE-004a to address reviewer feedback that the original CRUISE-004 was too large and that DDL operations should be isolated for better parallel execution and focused review. DDL operations (CREATE TABLE, DROP TABLE, ALTER TABLE ADD/DROP COLUMN) dynamically construct SQL from user-provided identifiers, creating a direct SQL injection attack surface. This task requires strict identifier validation (alphanumeric + underscore only, reserved word rejection) and column type whitelisting — security concerns entirely absent from 004a's read-only PRAGMA-based queries. Isolating this code in its own task and spawn instance (SPAWN-003b) provides: (1) **focused security review** of the injection prevention logic independently from connection pool boilerplate, (2) **parallel development** — 004b can start as soon as 004a completes and runs in a separate spawn instance, and (3) **smaller review surface** — reviewers can audit the security-critical DDL code without wading through unrelated connection management logic.

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

**Step 3: Create base template** - HTML layout with htmx script, basic CSS, nav structure. The base template MUST implement explicit CSRF token propagation for htmx:

1. Embed the server-generated CSRF token in a meta tag: `<meta name="csrf-token" content="{{ csrf_token }}">`.
2. Configure htmx globally to attach the token to **every** request using one of these two approaches (either is acceptable):
   - **Option A (recommended — `hx-headers` on `<body>`):** Render the body tag as `<body hx-headers='{"X-CSRF-Token": "{{ csrf_token }}"}'>`. This is the simplest approach and requires no JavaScript.
   - **Option B (`htmx:configRequest` event listener):** Add a `<script>` block: `document.body.addEventListener("htmx:configRequest", function(evt) { evt.detail.headers["X-CSRF-Token"] = document.querySelector('meta[name="csrf-token"]').content; });`.

This is **critical** because SameSite=Strict cookies alone are NOT sufficient CSRF protection for destructive DDL operations (DROP TABLE, DROP COLUMN). The explicit CSRF token is the **primary** defense; the cookie attributes are defense-in-depth only.

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

> **Split rationale:** Originally part of a single CRUISE-006 task. Split into 006a (auth handlers + router) and 006b (table/column handlers) to reduce bottleneck in the dependency graph. This task only depends on auth logic (002, 003) and templates (005), so it can start in parallel with the Database Layer (004a/004b), shortening the critical path.

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
- `login_submit(Form<LoginForm>)` - validates JWT, sets Secure HttpOnly SameSite=Strict session cookie (defense-in-depth), generates an explicit per-session CSRF token (cryptographically random 32-byte hex string stored server-side keyed to the session) as the primary CSRF defense, embeds it in the redirect response for template rendering, redirects to /
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

CSRF validation middleware: Implement as an Axum middleware layer applied to all protected routes. For every POST, PUT, and DELETE request:
1. Extract the `X-CSRF-Token` header value (sent automatically by htmx via the `hx-headers` body attribute or `htmx:configRequest` listener configured in the base template).
2. Look up the expected token from a concurrent `DashMap<SessionId, String>` (or `Arc<RwLock<HashMap<...>>>`) keyed by the session/user identifier extracted from the JWT claims.
3. Compare using a constant-time equality check to prevent timing attacks.
4. Return **403 Forbidden** if the header is missing, the token is not found server-side, or the values do not match.

This explicit per-request CSRF token validation is the **primary** CSRF defense. SameSite=Strict cookies are defense-in-depth only and must NOT be relied upon as the sole protection, especially for destructive DDL operations (DROP TABLE, DROP COLUMN).

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

> **Split rationale:** Separated from CRUISE-006a so that auth handler work isn't blocked by the Database Layer. This task depends on the DB layer (004b) and the router setup (006a), and wires in the data-manipulation routes once both are ready.

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

### Task CRUISE-008a: Auth E2E Test Specs

> **Split rationale:** Originally a single CRUISE-008 task covering all E2E test specs. Split into 008a (Auth), 008b (Tables), and 008c (Columns) because each feature area can be implemented and verified in parallel as the corresponding handlers are completed. Auth tests only depend on the auth handlers (CRUISE-006a), while table and column tests depend on their respective handlers (CRUISE-006b). This split enables parallel development and independent verification of each test suite.

**Files:**
- Create: `tests/e2e/specs/auth.spec.ts`

**Step 1: Write auth.spec.ts**

Tests:
- `should show login page when not authenticated` - GET / shows token input
- `should login with valid JWT token` - 5-minute token, verify dashboard shows username
- `should reject expired JWT token` - expired token shows error message
- `should reject invalid JWT token` - garbage string shows error
- `should logout successfully` - login, click logout, verify login page shown
- `.well-known/jwks.json returns valid JWKS` - API request, verify kty/alg/n/e fields

**Step 2: Run tests**

Run: `cd tests/e2e && npx playwright test specs/auth.spec.ts`
Expected: All auth tests pass

**Step 3: Commit**

```bash
git add tests/e2e/specs/auth.spec.ts
git commit -m "feat: auth E2E test specs"
```

---

### Task CRUISE-008b: Table E2E Test Specs

> **Split rationale:** See CRUISE-008a for split rationale. Table E2E tests are separated to allow parallel implementation with auth and column tests once the table handlers (CRUISE-006b) are ready.

**Files:**
- Create: `tests/e2e/specs/tables.spec.ts`

**Step 1: Write tables.spec.ts**

Tests (each test logs in with fresh JWT first):
- `should create a new table` - fill form, submit, verify table appears in list
- `should delete a table` - create table, accept confirm dialog, click delete, verify gone
- `should show table details when clicking table name` - create table, click name, verify detail view

**Step 2: Run tests**

Run: `cd tests/e2e && npx playwright test specs/tables.spec.ts`
Expected: All table tests pass

**Step 3: Commit**

```bash
git add tests/e2e/specs/tables.spec.ts
git commit -m "feat: table E2E test specs"
```

---

### Task CRUISE-008c: Column E2E Test Specs

> **Split rationale:** See CRUISE-008a for split rationale. Column E2E tests are separated to allow parallel implementation with auth and table tests once the column handlers (CRUISE-006b) are ready.

**Files:**
- Create: `tests/e2e/specs/columns.spec.ts`

**Step 1: Write columns.spec.ts**

Tests (each test logs in and creates a table first):
- `should add a column to a table` - fill column form, submit, verify column appears
- `should drop a column from a table` - add column, accept confirm, click drop, verify gone
- `should show correct column types` - add TEXT, INTEGER, REAL columns, verify types shown

**Step 2: Run tests**

Run: `cd tests/e2e && npx playwright test specs/columns.spec.ts`
Expected: All column tests pass

**Step 3: Commit**

```bash
git add tests/e2e/specs/columns.spec.ts
git commit -m "feat: column E2E test specs"
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

> **Note:** This task depends on CRUISE-008a, CRUISE-008b, and CRUISE-008c (the split E2E test specs). The original monolithic CRUISE-008 was split into three separate tasks — Auth, Table, and Column E2E tests — to allow parallel implementation and independent verification as the corresponding handlers are completed. See CRUISE-008a split rationale for details.

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
  pull-requests: write  # Required for posting test result summary as PR comment

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

> **Clarification: "Push test results to the repository for validation on the PR"**
>
> **Important distinction:** GitHub Actions artifacts are stored externally (in GitHub's artifact storage), not committed to the repository itself. They are accessible from the PR's workflow run page but are not part of the git history or branch contents. Artifacts alone do **not** satisfy a literal "in the repository" requirement.
>
> **Chosen approach:** We interpret "push test results for validation on the PR" as meaning **test results must be visible and actionable directly on the PR** — not that raw result files must be committed to a branch. We achieve this through three complementary mechanisms:
>
> 1. **PR comment summary (primary visibility)** — the `playwright-report-summary` action posts a pass/fail summary with test counts directly as a PR comment. This is the main way reviewers validate test results without leaving the PR page.
> 2. **GitHub Actions check status** — the workflow run reports pass/fail on the PR's Checks tab, blocking merge on failure when branch protection rules are configured. This enforces validation gating.
> 3. **GitHub Actions artifacts (supplementary)** — full Playwright HTML report and raw test-results uploaded with 30-day retention, downloadable from the workflow run summary. These provide drill-down detail but are stored externally, not in the repository.
>
> **Rationale:** Committing generated test result files to the branch is explicitly avoided because it pollutes git history with transient artifacts, creates merge conflicts, and is not standard CI/CD practice. The PR comment + check status approach provides stronger validation (automated gating + human-readable summary) than committed files would.
>
> **If literal in-repository storage is later required:** The CI workflow can be extended to commit a `test-results/summary.json` to the PR's source branch after test execution (requires `contents: write` permission and a `git push` step). This is not recommended but is a viable fallback.

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
    │
    ├─── Auth Path ────────────────────────┐
    │    CRUISE-002 (JWT + JWKS)           │
    │        └── CRUISE-003 (Auth MW)      │
    │                                      │
    ├─── DB Path ──────────────────────┐   │
    │    CRUISE-004a (Connection +     │   │
    │                 Queries)         │   │
    │        └── CRUISE-004b (DDL Ops) │   │
    │                                  │   │
    ├─── CRUISE-005 (Templates + htmx) ┤   │
    │                                  │   │
    │   ┌──────────────────────────────┘   │
    │   │                                  │
    │   │   CRUISE-006a (Auth Handlers ◄───┘ depends on 002, 003, 005
    │   │               + Router Setup)      (NO dependency on 004a/004b)
    │   │       │                            Can start while DB work continues
    │   │       │
    │   └───►CRUISE-006b (Table/Column ◄──── depends on 004b, 005, 006a
    │           Handlers + Full Wiring)      Merges both paths
    │
    ├── CRUISE-007 (E2E Test Setup)
    ├── CRUISE-009 (Lint CI)
    └── CRUISE-010 (Dep Review CI)

CRUISE-008a (Auth E2E Tests) ← depends on 006a, 007
    (can start before 006b is done — auth tests don't need table/column handlers)
CRUISE-008b (Table E2E Tests) ← depends on 006b, 007
CRUISE-008c (Column E2E Tests) ← depends on 006b, 007
CRUISE-011 (E2E CI) ← depends on 007, 008a, 008b, 008c
CRUISE-012 (Integration) ← depends on all above
```

**Parallelization opportunities after CRUISE-001:**
- CRUISE-002+003, CRUISE-004a, CRUISE-005, CRUISE-007, CRUISE-009, CRUISE-010 can all run in parallel.
- CRUISE-004b can start as soon as CRUISE-004a completes. The original monolithic CRUISE-004 task was split (per reviewer feedback) because it covered connection pooling, DDL operations, and query helpers — too large for effective parallel execution or focused review. The two subtasks are assigned to separate spawn instances (SPAWN-003a and SPAWN-003b) so the security-sensitive DDL operations and identifier validation in CRUISE-004b can be developed and reviewed independently from the basic connection/query logic in CRUISE-004a. This split reflects a deliberate security boundary: 004a has no SQL injection surface (read-only PRAGMAs), while 004b constructs DDL from user input and requires strict identifier validation — isolating this code enables focused security review of the injection prevention logic without the distraction of connection pool boilerplate.
- **Critical path optimization via 006a/006b split:** CRUISE-006a (Auth Handlers + Router Setup) depends only on 002, 003, and 005 — it does NOT depend on the Database Layer (004a/004b). This means auth handler development can proceed in parallel with database layer work, rather than being blocked by it. CRUISE-006b (Table/Column Handlers) is the only task that needs both the DB layer and the router setup. This split removes the original CRUISE-006 as a dependency-graph bottleneck and shortens the overall critical path.
- **Auth E2E tests unblocked earlier:** Because CRUISE-008a depends on CRUISE-006a (not 006b), auth E2E tests can begin as soon as the auth handlers and router are wired, without waiting for the table/column handlers or the full DB layer. This further reduces idle time on the critical path.

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
      "id": "SPAWN-003a",
      "name": "Database Connection & Queries",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-004a"]
    },
    {
      "id": "SPAWN-003b",
      "name": "Database DDL Operations (Security-Sensitive)",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-004b"]
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
      "id": "SPAWN-006a",
      "name": "E2E Test Infrastructure",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 600",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-007"]
    },
    {
      "id": "SPAWN-006b",
      "name": "Auth E2E Test Specs",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-008a"]
    },
    {
      "id": "SPAWN-006c",
      "name": "Table E2E Test Specs",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-008b"]
    },
    {
      "id": "SPAWN-006d",
      "name": "Column E2E Test Specs",
      "use_spawn_team": false,
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "task_ids": ["CRUISE-008c"]
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
        "Code compiles successfully",
        "NOTE: This middleware handles authentication only. CSRF protection (explicit per-session tokens via X-CSRF-Token header, validated on all POST/PUT/DELETE endpoints) is implemented separately in CRUISE-006a. Secure HttpOnly SameSite=Strict cookies are defense-in-depth only, not sufficient CSRF protection for destructive DDL operations."
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
      "spawn_instance": "SPAWN-003a"
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
      "spawn_instance": "SPAWN-003b"
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
        "POST /login validates JWT, sets Secure HttpOnly SameSite=Strict cookie (defense-in-depth), and generates an explicit per-session CSRF token as primary CSRF defense",
        "GET /logout clears cookie and redirects to /login",
        "GET / shows dashboard (protected)",
        "GET /static/* serves static files",
        "CSRF token generated per session and validated on all state-changing (POST/PUT/DELETE) protected endpoints via X-CSRF-Token header",
        "CSRF token embedded in base template via meta tag and attached to all htmx requests via hx-headers attribute on body or htmx:configRequest global event listener",
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
      "spawn_instance": "SPAWN-006a"
    },
    {
      "id": "CRUISE-008a",
      "subject": "Auth E2E Test Specs",
      "description": "Write Playwright auth test specs: auth.spec.ts (login with valid JWT, reject expired JWT, reject invalid JWT, logout, JWKS endpoint). All tests use short-lived (5-min) JWT tokens. Split from original CRUISE-008 to allow parallel implementation with table and column E2E tests.",
      "blocked_by": ["CRUISE-006a", "CRUISE-007"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Auth tests: valid login, expired token rejection, invalid token rejection, logout, JWKS endpoint validation",
        "All tests use programmatically-generated short-lived (300s) JWT tokens",
        "All auth tests pass when run against the application"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006b"
    },
    {
      "id": "CRUISE-008b",
      "subject": "Table E2E Test Specs",
      "description": "Write Playwright table test specs: tables.spec.ts (create table, delete table, view table details). Each test logs in with a fresh JWT first. Split from original CRUISE-008 to allow parallel implementation with auth and column E2E tests.",
      "blocked_by": ["CRUISE-006b", "CRUISE-007"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Table tests: create table, delete table with confirmation dialog, view table detail",
        "All tests use programmatically-generated short-lived (300s) JWT tokens",
        "All table tests pass when run against the application"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006c"
    },
    {
      "id": "CRUISE-008c",
      "subject": "Column E2E Test Specs",
      "description": "Write Playwright column test specs: columns.spec.ts (add column, drop column, verify column types). Each test logs in and creates a table first. Split from original CRUISE-008 to allow parallel implementation with auth and table E2E tests.",
      "blocked_by": ["CRUISE-006b", "CRUISE-007"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Column tests: add column, drop column with confirmation dialog, verify TEXT/INTEGER/REAL column types",
        "All tests use programmatically-generated short-lived (300s) JWT tokens",
        "All column tests pass when run against the application"
      ],
      "permissions": ["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
      "cli_params": "claude --model sonnet --allowedTools Read,Write,Edit,Bash,Glob,Grep --timeout 300",
      "spawn_instance": "SPAWN-006d"
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
      "description": "Create .github/workflows/e2e.yml that builds Rust server, installs Node.js + Playwright, generates JWT keys, runs E2E tests, uploads test results (playwright-report/ and test-results/) as artifacts with 30-day retention, and posts a test result summary as a PR comment for direct visibility. Triggered on all PRs. Caches Cargo dependencies. Workflow permissions include pull-requests:write for PR comment posting.",
      "blocked_by": ["CRUISE-007", "CRUISE-008a", "CRUISE-008b", "CRUISE-008c"],
      "complexity": "medium",
      "acceptance_criteria": [
        "Workflow triggers on pull_request to any branch",
        "Workflow permissions include contents:read and pull-requests:write",
        "Installs Rust stable toolchain and caches cargo dependencies",
        "Builds Rust server in release mode",
        "Sets up Node.js 20 and installs test dependencies with npm ci",
        "Generates JWT keys before running tests",
        "Runs Playwright tests with CI=true",
        "Uploads playwright-report and test-results as artifacts (always, even on failure)",
        "Artifact retention set to 30 days",
        "Posts test result summary as a PR comment via playwright-report-summary action for direct PR visibility",
        "NOTE: 'Push test results for validation on the PR' is satisfied by PR comment summary (direct visibility) + check status (merge gating) + artifacts (drill-down detail). Artifacts are stored externally, not committed to the repo — this is intentional to avoid polluting git history. See the plan clarification note in the CI workflow section for full rationale and a fallback commit-based approach if literal in-repo storage is later required."
      ],
      "permissions": ["Read", "Write", "Edit"],
      "cli_params": "claude --model haiku --allowedTools Read,Write,Edit --timeout 180",
      "spawn_instance": "SPAWN-007"
    },
    {
      "id": "CRUISE-012",
      "subject": "Integration Testing and Final Verification",
      "description": "End-to-end verification: generate keys, build server, verify healthz and JWKS endpoints manually via curl, run cargo test (all unit tests), run Playwright E2E tests. Fix any issues found. Ensure no compiler warnings. Final commit.",
      "blocked_by": ["CRUISE-001", "CRUISE-002", "CRUISE-003", "CRUISE-004a", "CRUISE-004b", "CRUISE-005", "CRUISE-006a", "CRUISE-006b", "CRUISE-007", "CRUISE-008a", "CRUISE-008b", "CRUISE-008c", "CRUISE-009", "CRUISE-010", "CRUISE-011"],
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
    "htmx CSRF vulnerability - hx-* requests bypass traditional form CSRF tokens; Secure HttpOnly SameSite=Strict cookies are defense-in-depth only and NOT sufficient as sole protection for destructive DDL operations (DROP TABLE, DROP COLUMN). Session cookie must include Secure (HTTPS-only), HttpOnly (no JS access), and SameSite=Strict flags. Primary mitigation: explicit per-session CSRF tokens generated server-side, embedded in templates via meta tags, and attached to all htmx requests via hx-headers attribute or htmx:configRequest global event. Server validates X-CSRF-Token header on all state-changing endpoints (POST/PUT/DELETE), returning 403 Forbidden if missing or invalid",
    "Super-linter may have different Rust edition expectations - need to configure RUST_EDITION or accept some false positives",
    "Askama template compile-time errors will fail the entire build - templates must be syntactically correct before integration",
    "CI build times may be slow due to Rust compilation - cargo cache action is critical for acceptable CI performance",
    "openssl dependency for key and certificate generation scripts only (not runtime JWKS parsing or tests) - must be available in CI runner (ubuntu-latest includes it). JWKS parsing uses the `rsa` crate at startup; tests use `rsa` + `rand` crates for ephemeral keypair generation."
  ]
}
```
