use crate::model::{Finding, SecurityRule, Severity};
use std::path::Path;

pub struct MissingTtlExtensionRule;

impl SecurityRule for MissingTtlExtensionRule {
    fn id(&self) -> &'static str {
        "SG001"
    }

    fn name(&self) -> &'static str {
        "Missing TTL Extension (State Expiration Hazard)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &'static str {
        "Soroban instance and persistent storage entries require periodic TTL extension. Writing to storage without calling extend_ttl risks state archival and contract lockup."
    }

    fn check(&self, path: &Path, content: &str, _ast: Option<&syn::File>) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if file uses Soroban storage in code (ignoring comments)
        let has_storage_write = content.lines().any(|line| {
            let t = line.trim();
            !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with("*") && (
                t.contains("storage().instance().set")
                || t.contains("storage().persistent().set")
                || t.contains("storage().instance().update")
                || t.contains("storage().persistent().update")
            )
        });

        if !has_storage_write {
            return findings;
        }

        // Check if extend_ttl is called in actual code (not just mentioned in comments)
        let has_ttl_extension = content.lines().any(|line| {
            let t = line.trim();
            !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with("*") && (
                t.contains("extend_ttl(") || t.contains("extend_ttl_threshold(")
            )
        });

        if !has_ttl_extension {
            // Find the line numbers where storage writes happen
            for (line_idx, line) in content.lines().enumerate() {
                let t = line.trim();
                if !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with("*") {
                    if t.contains("storage().instance().set")
                        || t.contains("storage().persistent().set")
                        || t.contains(".set(&")
                    {
                        findings.push(Finding {
                            rule_id: self.id().to_string(),
                            title: self.name().to_string(),
                            severity: self.severity(),
                            file_path: path.display().to_string(),
                            line: line_idx + 1,
                            column: 1,
                            message: "Storage mutation detected without any corresponding extend_ttl call in contract. Storage entry may expire and become permanently inaccessible.".to_string(),
                            snippet: t.to_string(),
                            remediation: "Call `env.storage().instance().extend_ttl(threshold, extend_to)` or `env.storage().persistent().extend_ttl(key, threshold, extend_to)` after storage updates.".to_string(),
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}
