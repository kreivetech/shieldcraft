//! # shieldcraft
//!
//! Defensive AI security, SQL query audit, data privacy masking, and sandbox guard for Rust.
//!
//! Provides essential safeguards for agentic systems, data pipelines, and LLM integrations:
//! - **SQL Query Audit**: Blocks destructive DDL/DML statements (`DROP`, `DELETE`, `UPDATE`, `TRUNCATE`, `ALTER`) and enforces read-only access.
//! - **Data Privacy & PII Masking**: Cellular redaction of sensitive values (CPF, CNPJ, Luhn-valid credit cards, BCrypt/Argon2 hashes, JWTs, AWS keys).
//! - **Security Context**: Configurable policies for blocked tables, blocked columns, and masked fields.
//! - **Execution Guard & Sandbox**: Blocks fork bombs, destructive file deletions (`rm -rf`), and isolates command execution.
//!
//! ## Quick Start
//!
//! ```
//! use shieldcraft::{is_safe_query, is_sensitive_value, mask_value, SecurityContext};
//!
//! // 1. Validate SQL queries before execution
//! assert!(is_safe_query("SELECT id, name FROM users WHERE active = 1"));
//! assert!(!is_safe_query("DROP TABLE users"));
//!
//! // 2. Mask sensitive PII and secrets
//! let raw = "$2a$12$e8Mc8K6Zg1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q";
//! assert!(is_sensitive_value(raw));
//! assert_eq!(mask_value(raw), "[REDACTED_SENSITIVE]");
//!
//! // 3. Build a security policy context
//! let context = SecurityContext::default()
//!     .with_blocked_tables(vec!["credentials".to_string()]);
//! assert!(context.audit_sql("SELECT * FROM credentials").is_err());
//! ```

pub mod context;
pub mod error;
pub mod guard;
pub mod mask;
pub mod sandbox;
pub mod sql;

pub use context::SecurityContext;
pub use error::ShieldError;
pub use guard::SafetyGuard;
pub use mask::{is_blocked_column, is_sensitive_value, mask_value, BLOCKED_COLUMNS};
pub use sandbox::{execute_safe_command, CommandExecutionResult};
pub use sql::{audit_sql, is_safe_query, DANGEROUS_SQL_KEYWORDS, SAFE_PRAGMAS};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_safety_rules() {
        assert!(is_safe_query("SELECT * FROM products"));
        assert!(is_safe_query("PRAGMA table_info(orders)"));
        assert!(!is_safe_query("TRUNCATE TABLE customers"));
        assert!(!is_safe_query("DELETE FROM logs WHERE 1=1"));
    }

    #[test]
    fn test_data_masking() {
        assert!(is_blocked_column("user_password"));
        assert!(is_blocked_column("access_token"));
        assert!(!is_blocked_column("order_total"));

        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzN";
        assert_eq!(mask_value(token), "[REDACTED_SENSITIVE]");
        assert_eq!(mask_value("safe_value"), "safe_value");
    }

    #[test]
    fn test_security_context_auditing() {
        let ctx = SecurityContext::default()
            .with_blocked_tables(vec!["salaries".to_string()]);

        assert!(ctx.audit_sql("SELECT name FROM employees").is_ok());
        assert!(ctx.audit_sql("SELECT amount FROM salaries").is_err());
        assert!(ctx.audit_sql("DROP TABLE employees").is_err());
    }

    #[test]
    fn test_safety_guard_intent_and_command() {
        let guard = SafetyGuard::new();
        assert!(guard.validate_intent("Help me analyze sales trends").is_ok());
        assert!(guard.validate_intent("generate a ransomware payload").is_err());

        assert!(guard.validate_command("cargo build").is_ok());
        assert!(guard.validate_command("rm -rf /").is_err());
        assert!(guard.validate_command(":(){ :|:& };:").is_err());
    }
}
