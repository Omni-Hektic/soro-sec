use crate::model::{Finding, SecurityRule, Severity};
use std::path::Path;

pub struct StorageCollisionRule;

impl SecurityRule for StorageCollisionRule {
    fn id(&self) -> &'static str {
        "SG005"
    }

    fn name(&self) -> &'static str {
        "Unstructured Storage Key (Key Collision Risk)"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &'static str {
        "Soroban contracts should use type-safe enum DataKey types for storage keys. Using raw symbols or unstructured identifiers increases the risk of key collisions and typos."
    }

    fn check(&self, path: &Path, content: &str, _ast: Option<&syn::File>) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if file has storage operations
        if !content.contains(".storage()") {
            return findings;
        }

        // Check if contract defines an enum DataKey
        let has_datakey_enum = content.contains("enum DataKey") || content.contains("enum StorageKey");

        if !has_datakey_enum {
            for (line_idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.contains("symbol_short!") && (trimmed.contains(".set(&") || trimmed.contains(".get(&")) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: self.name().to_string(),
                        severity: self.severity(),
                        file_path: path.display().to_string(),
                        line: line_idx + 1,
                        column: 1,
                        message: "Raw `symbol_short!` literal used as storage key instead of a typed DataKey enum.".to_string(),
                        snippet: trimmed.to_string(),
                        remediation: "Define a `#[contracttype] enum DataKey { ... }` to ensure compile-time type safety and prevent storage key collisions.".to_string(),
                    });
                    break;
                }
            }
        }

        findings
    }
}
