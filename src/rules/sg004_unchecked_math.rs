use crate::model::{Finding, SecurityRule, Severity};
use std::path::Path;

pub struct UncheckedMathRule;

impl SecurityRule for UncheckedMathRule {
    fn id(&self) -> &'static str {
        "SG004"
    }

    fn name(&self) -> &'static str {
        "Unchecked Arithmetic in Financial Logic"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "Direct arithmetic operations (+, -, *, /) on balance, fee, or token amount variables can overflow or panic in production. Use checked arithmetic (checked_add, checked_sub, checked_mul, checked_div) instead."
    }

    fn check(&self, path: &Path, content: &str, _ast: Option<&syn::File>) -> Vec<Finding> {
        let mut findings = Vec::new();

        let financial_keywords = ["balance", "amount", "fee", "reward", "shares", "total", "supply"];

        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Ignore comments and test modules
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with("*") {
                continue;
            }

            let lower = trimmed.to_lowercase();
            let has_financial_var = financial_keywords.iter().any(|k| lower.contains(k));

            if has_financial_var {
                // Check for raw operators like balance + amount, balance - fee, amount * rate
                let has_raw_op = (trimmed.contains(" + ") || trimmed.contains(" - ") || trimmed.contains(" * ") || trimmed.contains(" / "))
                    && !trimmed.contains("checked_")
                    && !trimmed.contains("saturating_")
                    && !trimmed.contains("wrapping_");

                if has_raw_op && (trimmed.contains("let ") || trimmed.contains(" = ")) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: self.name().to_string(),
                        severity: self.severity(),
                        file_path: path.display().to_string(),
                        line: line_idx + 1,
                        column: 1,
                        message: "Raw arithmetic operator used in financial balance/amount calculation.".to_string(),
                        snippet: trimmed.to_string(),
                        remediation: "Replace raw arithmetic with `.checked_add()`, `.checked_sub()`, `.checked_mul()`, or `.checked_div()` and handle None explicitly.".to_string(),
                    });
                }
            }
        }

        findings
    }
}
