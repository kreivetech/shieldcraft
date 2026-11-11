use crate::error::ShieldError;
use regex::Regex;

pub struct SafetyGuard {
    hash_crack_regex: Regex,
    rev_shell_regex: Regex,
    obfuscation_regex: Regex,
    sqli_regex: Regex,
}

impl Default for SafetyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGuard {
    pub fn new() -> Self {
        SafetyGuard {
            hash_crack_regex: Regex::new(r"(?i)\b(crack|brute|rainbow)\b.*\b(hash|md5|sha|bcrypt|password)\b")
                .expect("Valid regex"),
            rev_shell_regex: Regex::new(r"(?i)bash\s+-i\s+>\s+&\s+/dev/tcp/[\d.]+/\d+\s+0\s+>\s+&\s+1")
                .expect("Valid regex"),
            obfuscation_regex: Regex::new(r"(?i)eval\(atob\(.*?\)\)")
                .expect("Valid regex"),
            sqli_regex: Regex::new(r"(?i)SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?\s+=\s+'.*?'\s+OR\s+'1'='1'")
                .expect("Valid regex"),
        }
    }

    pub fn validate_intent(&self, prompt: &str) -> Result<(), ShieldError> {
        let lower = prompt.to_lowercase();

        let blocked_keywords = [
            "reverse shell", "backdoor", "ransomware", "keylogger", "trojan",
            "sql injection payload", "xss payload", "crack md5", "crack sha", "hashcat",
            "password cracker", "bypass auth", "exploit generation", "shellcode",
            "metasploit", "payload generator", "create malware",
        ];

        for keyword in &blocked_keywords {
            if lower.contains(keyword) {
                return Err(ShieldError::MaliciousIntent(format!(
                    "Request related to '{}' blocked for safety.",
                    keyword
                )));
            }
        }

        if self.hash_crack_regex.is_match(prompt) {
            return Err(ShieldError::MaliciousIntent(
                "Hash cracking or brute force requests are blocked.".to_string(),
            ));
        }

        Ok(())
    }

    pub fn sanitize_response(&self, text: &str) -> String {
        let mut sanitized = text.to_string();

        if self.rev_shell_regex.is_match(&sanitized) {
            sanitized = self.rev_shell_regex.replace_all(
                &sanitized,
                "[BLOCKED: Code identified as Reverse Shell removed for security]",
            ).to_string();
        }

        if self.obfuscation_regex.is_match(&sanitized) {
            sanitized = self.obfuscation_regex.replace_all(
                &sanitized,
                "[BLOCKED: Code identified as Obfuscated Execution removed for security]",
            ).to_string();
        }

        if self.sqli_regex.is_match(&sanitized) {
            sanitized = self.sqli_regex.replace_all(
                &sanitized,
                "[BLOCKED: Code identified as SQL Injection removed for security]",
            ).to_string();
        }

        sanitized
    }

    pub fn validate_command(&self, cmd: &str) -> Result<(), ShieldError> {
        let cmd_clean = cmd.trim();
        let lower = cmd_clean.to_lowercase();

        // 1. Fork bomb patterns
        if lower.contains(":(){") || lower.contains(":|:&") {
            return Err(ShieldError::CommandBlocked(
                "Suspicious Fork Bomb pattern detected.".to_string(),
            ));
        }

        // 2. Formatting and disk partitioning/raw writing commands
        let disk_commands = ["mkfs", "fdisk", "parted", "format"];
        for term in &disk_commands {
            if lower.contains(term)
                && (lower.contains("/dev/") || lower.contains(" c:") || lower.contains(" d:"))
            {
                return Err(ShieldError::CommandBlocked(format!(
                    "Destructive disk operation detected ({}).",
                    term
                )));
            }
        }
        if lower.contains("dd ") && (lower.contains("of=/dev/") || lower.contains("of=//")) {
            return Err(ShieldError::CommandBlocked(
                "Direct disk block writing (dd) detected.".to_string(),
            ));
        }

        // 3. System shutdown/reboot
        let system_halt_commands = ["shutdown", "reboot", "poweroff", "init 0", "init 6"];
        for term in &system_halt_commands {
            if lower.contains(term) {
                return Err(ShieldError::CommandBlocked(format!(
                    "System shutdown or reboot command detected ({}).",
                    term
                )));
            }
        }

        // 4. Destructive deletion (rm / del / rmdir)
        if lower.contains("rm ") {
            let parts: Vec<&str> = lower.split_whitespace().collect();
            let mut has_recursive = false;
            for part in &parts {
                if part.starts_with('-') && (part.contains('r') || part.contains('f')) {
                    has_recursive = true;
                }
            }
            if has_recursive {
                let destructive_targets = [
                    "/", "/*", ".", "..", "./*", "../*", "*", "/etc", "/bin", "/sbin", "/lib",
                    "/usr", "/var", "/boot", "/sys", "/proc", "/dev",
                ];
                for target in &destructive_targets {
                    if parts.contains(target) || parts.iter().any(|p| p.ends_with(target)) {
                        return Err(ShieldError::CommandBlocked(format!(
                            "Recursive/forced removal of a critical directory detected (target: {}).",
                            target
                        )));
                    }
                }
            }

            // Block deleting critical project files
            let critical_files = ["package.json", "cargo.toml"];
            for file in &critical_files {
                if parts.contains(file) || parts.iter().any(|p| p.ends_with(file)) {
                    return Err(ShieldError::CommandBlocked(format!(
                        "Attempt to delete critical project configuration file ({}).",
                        file
                    )));
                }
            }
        }

        if lower.contains("del ") || lower.contains("rd ") || lower.contains("rmdir ") {
            let parts: Vec<&str> = lower.split_whitespace().collect();
            if lower.contains('*')
                || lower.contains("/s")
                || lower.contains("/f")
                || lower.contains("/q")
            {
                let windows_critical = [
                    "c:\\", "c:\\windows", "c:\\windows\\system32", "d:\\", "\\",
                ];
                for target in &windows_critical {
                    if parts.contains(target) || parts.iter().any(|p| p.contains(target)) {
                        return Err(ShieldError::CommandBlocked(format!(
                            "Forced/bulk removal in Windows system directory detected (target: {}).",
                            target
                        )));
                    }
                }
            }

            let critical_files = ["package.json", "cargo.toml"];
            for file in &critical_files {
                if parts.contains(file) || parts.iter().any(|p| p.ends_with(file)) {
                    return Err(ShieldError::CommandBlocked(format!(
                        "Attempt to delete critical project configuration file ({}).",
                        file
                    )));
                }
            }
        }

        // 5. Destructive Database Commands
        let destructive_db_keywords = [
            "drop database", "drop table", "truncate table", "drop schema", "dropdb ", "createdb ",
        ];
        for keyword in &destructive_db_keywords {
            if lower.contains(keyword) {
                return Err(ShieldError::CommandBlocked(format!(
                    "Destructive database operation detected ({}).",
                    keyword
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_intent_safe() {
        let guard = SafetyGuard::new();
        assert!(guard.validate_intent("explain this clean function").is_ok());
    }

    #[test]
    fn test_validate_intent_blocked_keyword() {
        let guard = SafetyGuard::new();
        let err = guard.validate_intent("how to create a ransomware?").unwrap_err();
        assert!(err.to_string().contains("ransomware"));
    }

    #[test]
    fn test_validate_intent_hash_crack() {
        let guard = SafetyGuard::new();
        let err = guard
            .validate_intent("how to brute force this bcrypt password?")
            .unwrap_err();
        assert!(err.to_string().contains("Hash cracking"));
    }

    #[test]
    fn test_sanitize_response_clean() {
        let guard = SafetyGuard::new();
        let text = "let x = 10;";
        assert_eq!(guard.sanitize_response(text), text);
    }

    #[test]
    fn test_sanitize_response_dirty() {
        let guard = SafetyGuard::new();
        let text = "run this command: bash -i > & /dev/tcp/127.0.0.1/4444 0 > & 1 and eval(atob('abc'))";
        let sanitized = guard.sanitize_response(text);
        assert!(sanitized.contains("[BLOCKED: Code identified as Reverse Shell"));
        assert!(sanitized.contains("[BLOCKED: Code identified as Obfuscated Execution"));
    }

    #[test]
    fn test_validate_command_destructive() {
        let guard = SafetyGuard::new();
        assert!(guard.validate_command("cargo test").is_ok());
        assert!(guard.validate_command("npm install").is_ok());

        assert!(guard.validate_command("rm -rf /").is_err());
        assert!(guard.validate_command("rm -rf .").is_err());
        assert!(guard.validate_command("rm -rf critical_folder/*").is_err());
        assert!(guard.validate_command("rm package.json").is_err());
        assert!(guard.validate_command("del /f /s /q c:\\windows").is_err());
        assert!(guard.validate_command("drop database users;").is_err());
        assert!(guard.validate_command("drop table logs;").is_err());
        assert!(guard.validate_command("shutdown -h now").is_err());
        assert!(guard.validate_command("mkfs.ext4 /dev/sda1").is_err());
    }
}
