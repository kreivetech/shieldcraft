use catfive::{string, Validator};
use regex::Regex;
use std::sync::LazyLock;

/// Default list of column names that should always be redacted.
pub const BLOCKED_COLUMNS: &[&str] = &[
    "password", "passwd", "secret", "token", "key", "hash", "salt",
    "credit_card", "cc_number", "cvv", "ssn", "social_security",
    "access_token", "refresh_token", "api_key", "private_key",
    "cpf", "pin",
    // Wildcards
    "*_password", "*_key", "*_secret", "*_token", "*_hash",
    "*_cpf", "*_ssn", "*_pin", "*_cvv",
];

static RE_SENSITIVE_VALUES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // BCrypt / Argon2 / SCrypt hashes
        Regex::new(r"^\$2[aby]\$\d{2}\$.{20,}$").unwrap(),
        Regex::new(r"^\$argon2").unwrap(),
        // JSON Web Tokens (JWT)
        Regex::new(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").unwrap(),
        // AWS Access Keys
        Regex::new(r"^AKIA[0-9A-Z]{16}$").unwrap(),
    ]
});

static CPF_VALIDATOR: LazyLock<catfive::string::StringValidator> = LazyLock::new(|| {
    string().spek("[CPF]")
});

static CNPJ_VALIDATOR: LazyLock<catfive::string::StringValidator> = LazyLock::new(|| {
    string().spek("[CNPJ]")
});

static LUHN_VALIDATOR: LazyLock<catfive::string::StringValidator> = LazyLock::new(|| {
    string().spek("[LUHN]")
});

/// Returns true if the column name matches a blocked pattern or wildcard.
pub fn is_blocked_column(name: &str) -> bool {
    let lower = name.to_lowercase();
    BLOCKED_COLUMNS.iter().any(|&pattern| {
        if let Some(stripped) = pattern.strip_prefix('*') {
            let suffix = stripped.to_lowercase();
            lower.ends_with(&suffix)
        } else {
            lower == pattern.to_lowercase()
        }
    })
}

/// Returns true if the raw string value matches a sensitive pattern (hashes, tokens, CPF, CNPJ, credit card).
pub fn is_sensitive_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    if RE_SENSITIVE_VALUES.iter().any(|re| re.is_match(trimmed)) {
        return true;
    }

    // Brazilian CPF and CNPJ validation via Catfive
    if CPF_VALIDATOR.validate(trimmed).is_ok() || CNPJ_VALIDATOR.validate(trimmed).is_ok() {
        return true;
    }

    // Credit card / LUHN algorithm check via Catfive
    let digits_only: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits_only.len() >= 13
        && digits_only.len() <= 19
        && LUHN_VALIDATOR.validate(digits_only.as_str()).is_ok()
    {
        return true;
    }

    false
}

/// Masks a value, replacing sensitive information with a standard redaction marker.
pub fn mask_value(value: &str) -> String {
    let trimmed = value.trim();
    if is_sensitive_value(trimmed) {
        "[REDACTED_SENSITIVE]".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_column_detection() {
        assert!(is_blocked_column("password"));
        assert!(is_blocked_column("user_password"));
        assert!(is_blocked_column("api_key"));
        assert!(is_blocked_column("auth_token"));
        assert!(is_blocked_column("customer_cpf"));
        assert!(!is_blocked_column("username"));
        assert!(!is_blocked_column("email"));
        assert!(!is_blocked_column("created_at"));
    }

    #[test]
    fn test_sensitive_value_detection() {
        // BCrypt
        assert!(is_sensitive_value("$2a$12$e8Mc8K6Zg1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q7V8g1Q"));
        // JWT
        assert!(is_sensitive_value("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzN"));
        // AWS Key
        assert!(is_sensitive_value("AKIAIOSFODNN7EXAMPLE"));
        // Plain text
        assert!(!is_sensitive_value("Hello world"));
        assert!(!is_sensitive_value("john.doe@example.com"));
    }
}
