use crate::model::{Finding, SecurityRule, Severity};
use std::path::Path;

pub struct CeiViolationRule;

impl SecurityRule for CeiViolationRule {
    fn id(&self) -> &'static str {
        "SG003"
    }

    fn name(&self) -> &'static str {
        "Checks-Effects-Interactions (CEI) Pattern Violation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "External contract calls or token transfers must occur AFTER internal contract state is updated. Mutating state after external invocations opens the contract to reentrancy vulnerabilities and state desynchronization."
    }

    fn check(&self, path: &Path, content: &str, _ast: Option<&syn::File>) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan functions line by line for cross-contract invocation followed by storage mutation
        let mut current_fn: Option<String> = None;
        let mut saw_external_call_at: Option<(usize, String)> = None;

        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("pub fn ") || (trimmed.starts_with("fn ") && trimmed.contains('(')) {
                // Reset on new function
                current_fn = Some(trimmed.split('(').next().unwrap_or("").replace("pub fn ", "").replace("fn ", "").trim().to_string());
                saw_external_call_at = None;
            }

            // Detect external client call or invocation
            let is_external_call = (trimmed.contains("Client::new") && (trimmed.contains(".transfer") || trimmed.contains(".invoke")))
                || trimmed.contains("env.invoke_contract")
                || trimmed.contains("token::Client::new");

            if is_external_call && saw_external_call_at.is_none() {
                saw_external_call_at = Some((line_idx + 1, trimmed.to_string()));
            }

            // Detect subsequent storage mutation
            let is_storage_write = trimmed.contains(".storage().instance().set")
                || trimmed.contains(".storage().persistent().set")
                || trimmed.contains(".storage().temporary().set");

            if is_storage_write {
                if let Some((call_line, ref call_snippet)) = saw_external_call_at {
                    let fn_label = current_fn.clone().unwrap_or_else(|| "function".to_string());
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: self.name().to_string(),
                        severity: self.severity(),
                        file_path: path.display().to_string(),
                        line: line_idx + 1,
                        column: 1,
                        message: format!(
                            "Storage state updated on line {} after external contract call on line {} in `{}` (CEI violation).",
                            line_idx + 1, call_line, fn_label
                        ),
                        snippet: format!("External call (L{}): {}\nState update (L{}): {}", call_line, call_snippet, line_idx + 1, trimmed),
                        remediation: "Follow Checks-Effects-Interactions: update all local storage balances and flags BEFORE invoking external contracts or token transfers.".to_string(),
                    });
                    // Only flag once per function
                    saw_external_call_at = None;
                }
            }
        }

        findings
    }
}
