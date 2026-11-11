# shieldcraft

[![Crates.io](https://img.shields.io/crates/v/shieldcraft.svg)](https://crates.io/crates/shieldcraft)
[![Docs.rs](https://docs.rs/shieldcraft/badge.svg)](https://docs.rs/shieldcraft)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Defensive AI security, SQL query audit, data privacy masking, and sandbox guard for Rust.

Built and maintained by **[Kreive Tech](https://kreive.com.br)**.

---

## Features

- **SQL Safety & Query Audit**:
  - Deterministic AST and pattern-based verification ensuring only safe read-only statements (`SELECT`, `WITH`, safe introspection `PRAGMA`) are permitted.
  - Strict blocking of destructive statements (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE`, etc.).
  - Blocked tables enforcement to prevent unauthorized table access.
- **Cellular Data Masking & PII Redaction**:
  - Detection of cryptographic hashes (BCrypt, Argon2, SCrypt), JWTs, and API credentials.
  - Algorithmic validation and redaction of Brazilian CPF and CNPJ documents.
  - Luhn checksum verification for credit card number detection.
  - Configurable blocked and masked column patterns with wildcard support (`*_password`, `*_token`, `*_cpf`).
- **Policy Context (`SecurityContext`)**:
  - Unified security rules for data pipelines, agent analytics, and database drivers.
- **Execution Guard & Command Sandbox**:
  - Command validation blocking fork bombs, disk formatting (`mkfs`, `dd`), system shutdown, and recursive destructive deletions (`rm -rf /`).
  - Safe subprocess execution with configurable timeout limits and capped output buffers.

---

## Installation

Add `shieldcraft` to your `Cargo.toml`:

```toml
[dependencies]
shieldcraft = "0.1.0"
```

---

## Quick Examples

### 1. SQL Query Safety Validation

```rust
use shieldcraft::is_safe_query;

fn main() {
    // Allowed: read-only operations
    assert!(is_safe_query("SELECT id, name FROM users WHERE active = 1"));
    assert!(is_safe_query("WITH total AS (SELECT count(*) FROM orders) SELECT * FROM total"));
    assert!(is_safe_query("PRAGMA table_info(users)"));

    // Blocked: destructive operations
    assert!(!is_safe_query("DROP TABLE users"));
    assert!(!is_safe_query("DELETE FROM users WHERE id = 1"));
    assert!(!is_safe_query("UPDATE users SET admin = 1"));
}
```

---

### 2. PII Detection and Data Masking

```rust
use shieldcraft::{is_blocked_column, is_sensitive_value, mask_value};

fn main() {
    // Check column names
    assert!(is_blocked_column("user_password"));
    assert!(is_blocked_column("api_key"));

    // Check raw values
    let hash = "$2a$12$e8Mc8K6Zg1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q";
    assert!(is_sensitive_value(hash));
    assert_eq!(mask_value(hash), "[REDACTED_SENSITIVE]");
}
```

---

### 3. Security Policy Context

```rust
use shieldcraft::SecurityContext;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = SecurityContext::default()
        .with_blocked_tables(vec!["passwords".to_string(), "api_tokens".to_string()])
        .with_masked_columns(vec!["salary".to_string(), "*_secret".to_string()]);

    // Passes: queries allowed table
    context.audit_sql("SELECT id, name FROM employees")?;

    // Fails: attempts to access blocked table
    assert!(context.audit_sql("SELECT * FROM passwords").is_err());

    Ok(())
}
```

---

### 4. Malicious Command Guard

```rust
use shieldcraft::SafetyGuard;

fn main() {
    let guard = SafetyGuard::new();

    // Normal commands are allowed
    assert!(guard.validate_command("cargo test").is_ok());

    // Destructive commands are blocked
    assert!(guard.validate_command("rm -rf /").is_err());
    assert!(guard.validate_command(":(){ :|:& };:").is_err());
}
```

---

## Sponsor & Support

Developed by **[Kreive Tech](https://kreive.com.br)**.

For questions, enterprise security support, or contributions, reach out to `contact@kreive.com.br`.

---

## License

MIT © [Kreive Tech](https://kreive.com.br)
