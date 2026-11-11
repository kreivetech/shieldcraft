use crate::error::ShieldError;
use crate::mask::is_blocked_column as default_is_blocked_column;
use crate::sql::{audit_sql as default_audit_sql, is_safe_query as default_is_safe_query};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecurityContext {
    pub blocked_columns: Vec<String>,
    pub blocked_tables: Vec<String>,
    pub masked_columns: Vec<String>,
}

impl SecurityContext {
    pub fn new(
        blocked_columns: Vec<String>,
        blocked_tables: Vec<String>,
        masked_columns: Vec<String>,
    ) -> Self {
        Self {
            blocked_columns,
            blocked_tables,
            masked_columns,
        }
    }

    pub fn with_blocked_columns(mut self, cols: Vec<String>) -> Self {
        self.blocked_columns = cols;
        self
    }

    pub fn with_blocked_tables(mut self, tables: Vec<String>) -> Self {
        self.blocked_tables = tables;
        self
    }

    pub fn with_masked_columns(mut self, cols: Vec<String>) -> Self {
        self.masked_columns = cols;
        self
    }

    pub fn is_blocked_column(&self, name: &str) -> bool {
        let lower = name.to_lowercase();

        // Check user config first
        if self.blocked_columns.iter().any(|p| {
            if let Some(stripped) = p.strip_prefix('*') {
                lower.ends_with(&stripped.to_lowercase())
            } else {
                lower == p.to_lowercase()
            }
        }) {
            return true;
        }

        // Fallback to default blocked columns
        default_is_blocked_column(name)
    }

    pub fn is_masked_column(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.masked_columns.iter().any(|p| {
            if let Some(stripped) = p.strip_prefix('*') {
                lower.ends_with(&stripped.to_lowercase())
            } else {
                lower == p.to_lowercase()
            }
        })
    }

    pub fn is_blocked_table(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.blocked_tables.iter().any(|t| lower == t.to_lowercase())
    }

    pub fn is_safe_query(&self, sql: &str) -> bool {
        default_is_safe_query(sql)
    }

    pub fn audit_sql(&self, sql: &str) -> Result<(), ShieldError> {
        default_audit_sql(sql, &self.blocked_tables)
    }
}
