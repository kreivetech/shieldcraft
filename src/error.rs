use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ShieldError {
    #[error("SQL query security violation: {0}")]
    SqlViolation(String),

    #[error("Access to blocked table '{0}' is restricted")]
    BlockedTable(String),

    #[error("Malicious or non-defensive intent detected: {0}")]
    MaliciousIntent(String),

    #[error("Command execution blocked: {0}")]
    CommandBlocked(String),

    #[error("Command '{command}' execution failed: {error}")]
    CommandExecution { command: String, error: String },

    #[error("Execution timed out: {0}")]
    Timeout(String),

    #[error("Internal security error: {0}")]
    Custom(String),
}
