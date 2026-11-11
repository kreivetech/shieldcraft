use crate::error::ShieldError;
use crate::guard::SafetyGuard;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandExecutionResult {
    pub command: String,
    pub success: bool,
    pub output: String,
    pub exit_code: Option<i32>,
}

/// Executes a safe terminal command inside the specified working directory.
/// Validates the command using `SafetyGuard::validate_command` before spawning.
pub async fn execute_safe_command(
    cmd: &str,
    working_dir: &Path,
    timeout_duration: Option<Duration>,
) -> Result<CommandExecutionResult, ShieldError> {
    let safety = SafetyGuard::new();
    safety.validate_command(cmd)?;

    let timeout = timeout_duration.unwrap_or(Duration::from_secs(120));

    let child = if cfg!(target_os = "windows") {
        tokio::process::Command::new("cmd")
            .args(["/C", cmd])
            .current_dir(working_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    } else {
        tokio::process::Command::new("sh")
            .args(["-c", cmd])
            .current_dir(working_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    };

    let child = match child {
        Ok(c) => c,
        Err(e) => {
            return Err(ShieldError::CommandExecution {
                command: cmd.to_string(),
                error: format!("Failed to spawn process: {}", e),
            })
        }
    };

    let output_res = tokio::time::timeout(timeout, child.wait_with_output()).await;

    match output_res {
        Ok(Ok(output)) => {
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let mut combined = String::new();
            if !stdout_str.is_empty() {
                combined.push_str(&stdout_str);
            }
            if !stderr_str.is_empty() {
                if !combined.is_empty() && !combined.ends_with('\n') {
                    combined.push('\n');
                }
                combined.push_str(&stderr_str);
            }

            // Cap output to 50KB to protect memory and UI rendering
            let capped_output = if combined.len() > 50_000 {
                format!("{}...\n[Output truncated at 50KB]", &combined[..50_000])
            } else {
                combined
            };

            Ok(CommandExecutionResult {
                command: cmd.to_string(),
                success: output.status.success(),
                output: capped_output,
                exit_code: output.status.code(),
            })
        }
        Ok(Err(e)) => Err(ShieldError::CommandExecution {
            command: cmd.to_string(),
            error: format!("Process execution error: {}", e),
        }),
        Err(_) => Err(ShieldError::Timeout(format!(
            "Command '{}' timed out after {} seconds.",
            cmd,
            timeout.as_secs()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_execute_safe_command_echo() {
        let dir = tempdir().unwrap();
        let result = execute_safe_command("echo test_safe_execution", dir.path(), None)
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.output.contains("test_safe_execution"));
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_execute_blocked_command() {
        let dir = tempdir().unwrap();
        let result = execute_safe_command("rm -rf /", dir.path(), None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ShieldError::CommandBlocked(_)));
    }
}
