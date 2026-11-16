use crate::model::{ScanReport, Severity};
use anyhow::Result;
use serde_json::json;

pub fn render(report: &ScanReport) -> Result<String> {
    let results: Vec<_> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Informational => "note",
            };

            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": format!("{}: {}", f.title, f.message)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path
                        },
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column
                        }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "soro-sec",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/Omni-Hektic/soro-sec",
                    "rules": [
                        {
                            "id": "SG001",
                            "name": "MissingTtlExtension",
                            "shortDescription": { "text": "Missing TTL Extension on storage entries" }
                        },
                        {
                            "id": "SG002",
                            "name": "MissingRequireAuth",
                            "shortDescription": { "text": "Missing require_auth() authorization" }
                        },
                        {
                            "id": "SG003",
                            "name": "CeiViolation",
                            "shortDescription": { "text": "Checks-Effects-Interactions pattern violation" }
                        },
                        {
                            "id": "SG004",
                            "name": "UncheckedMath",
                            "shortDescription": { "text": "Unchecked arithmetic operations in financial logic" }
                        },
                        {
                            "id": "SG005",
                            "name": "StorageCollision",
                            "shortDescription": { "text": "Unstructured storage keys" }
                        }
                    ]
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}
