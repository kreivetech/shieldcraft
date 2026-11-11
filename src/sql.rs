use crate::error::ShieldError;
use regex::Regex;
use std::sync::LazyLock;

pub const DANGEROUS_SQL_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT",
    "REVOKE", "EXEC", "EXECUTE",
];

pub const SAFE_PRAGMAS: &[&str] = &["TABLE_INFO", "INDEX_LIST", "FOREIGN_KEY_LIST"];

static DANGEROUS_REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    DANGEROUS_SQL_KEYWORDS
        .iter()
        .map(|kw| Regex::new(&format!(r"(?i)\b{}\b", kw)).expect("valid regex"))
        .collect()
});

/// Validates whether a SQL query is a safe read-only operation.
///
/// Only permits `SELECT`, `WITH ... SELECT`, and safe introspection `PRAGMA` statements.
/// Blocks destructive DDL/DML statements (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, etc.).
pub fn is_safe_query(sql: &str) -> bool {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return false;
    }

    let upper = trimmed.to_uppercase();

    // Allow SELECT, WITH, and PRAGMA
    if !upper.starts_with("SELECT") && !upper.starts_with("WITH ") && !upper.starts_with("PRAGMA ") {
        return false;
    }

    // Block dangerous keywords
    for re in DANGEROUS_REGEXES.iter() {
        if re.is_match(trimmed) {
            return false;
        }
    }

    // Restrict PRAGMAs to safe schema inspection
    if upper.starts_with("PRAGMA ") {
        if !SAFE_PRAGMAS.iter().any(|safe| upper.contains(safe)) {
            return false;
        }
    }

    true
}

/// Audits a SQL query against read-only safety rules and a list of blocked tables.
pub fn audit_sql(sql: &str, blocked_tables: &[String]) -> Result<(), ShieldError> {
    if !is_safe_query(sql) {
        return Err(ShieldError::SqlViolation(
            "SQL is not a safe read-only statement or contains destructive keywords".to_string(),
        ));
    }

    let lower_sql = sql.to_lowercase();
    for table in blocked_tables {
        let pattern = format!(r"(?i)\b{}\b", regex::escape(table));
        if let Ok(re) = Regex::new(&pattern) {
            if re.is_match(&lower_sql) {
                return Err(ShieldError::BlockedTable(table.clone()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_queries() {
        assert!(is_safe_query("SELECT * FROM users"));
        assert!(is_safe_query("SELECT id, name FROM accounts WHERE active = 1"));
        assert!(is_safe_query("WITH summary AS (SELECT count(*) FROM orders) SELECT * FROM summary"));
        assert!(is_safe_query("PRAGMA table_info(users)"));
        assert!(is_safe_query("PRAGMA foreign_key_list(orders)"));
    }

    #[test]
    fn test_destructive_queries_blocked() {
        assert!(!is_safe_query("DROP TABLE users"));
        assert!(!is_safe_query("DELETE FROM users WHERE 1=1"));
        assert!(!is_safe_query("UPDATE users SET password = '123'"));
        assert!(!is_safe_query("INSERT INTO users VALUES (1, 'admin')"));
        assert!(!is_safe_query("TRUNCATE TABLE users"));
        assert!(!is_safe_query("ALTER TABLE users ADD COLUMN secret text"));
        assert!(!is_safe_query("CREATE TABLE backdoor (id int)"));
        assert!(!is_safe_query("GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'"));
    }

    #[test]
    fn test_unsafe_pragma_blocked() {
        assert!(!is_safe_query("PRAGMA writable_schema = 1"));
        assert!(!is_safe_query("PRAGMA journal_mode = OFF"));
    }

    #[test]
    fn test_audit_sql_blocked_table() {
        let blocked = vec!["passwords".to_string(), "secrets".to_string()];
        assert!(audit_sql("SELECT * FROM users", &blocked).is_ok());
        assert!(matches!(
            audit_sql("SELECT * FROM passwords", &blocked),
            Err(ShieldError::BlockedTable(tbl)) if tbl == "passwords"
        ));
    }
}
