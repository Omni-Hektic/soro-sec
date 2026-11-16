use crate::model::{ScanReport, Severity};
use anyhow::Result;

pub fn render(report: &ScanReport) -> Result<String> {
    let mut out = String::new();

    out.push_str("# Soro-Sec Smart Contract Security Report\n\n");
    out.push_str(&format!("- **Target Path:** `{}`\n", report.target_path));
    out.push_str(&format!("- **Files Scanned:** {}\n", report.summary.total_files));
    out.push_str(&format!("- **Scan Duration:** {} ms\n\n", report.duration_ms));

    out.push_str("## Executive Summary\n\n");
    out.push_str("| Severity | Findings |\n");
    out.push_str("| :--- | :--- |\n");
    out.push_str(&format!("| 🔴 Critical | {} |\n", report.summary.critical_count));
    out.push_str(&format!("| 🟠 High | {} |\n", report.summary.high_count));
    out.push_str(&format!("| 🟡 Medium | {} |\n", report.summary.medium_count));
    out.push_str(&format!("| 🔵 Low | {} |\n", report.summary.low_count));
    out.push_str(&format!("| ⚪ Informational | {} |\n\n", report.summary.info_count));

    if report.findings.is_empty() {
        out.push_str("✅ **Clean Bill of Health:** No vulnerabilities or policy violations detected.\n");
        return Ok(out);
    }

    out.push_str("## Detailed Findings\n\n");
    for (idx, f) in report.findings.iter().enumerate() {
        let icon = match f.severity {
            Severity::Critical => "🔴 CRITICAL",
            Severity::High => "🟠 HIGH",
            Severity::Medium => "🟡 MEDIUM",
            Severity::Low => "🔵 LOW",
            Severity::Informational => "⚪ INFO",
        };

        out.push_str(&format!("### {}. [{}] {}: {}\n\n", idx + 1, icon, f.rule_id, f.title));
        out.push_str(&format!("- **Location:** `{}:{}:{}`\n", f.file_path, f.line, f.column));
        out.push_str(&format!("- **Description:** {}\n", f.message));

        if !f.snippet.is_empty() {
            out.push_str(&format!("\n```rust\n{}\n```\n", f.snippet));
        }

        out.push_str(&format!("\n> [!TIP]\n> **Remediation:** {}\n\n---\n\n", f.remediation));
    }

    Ok(out)
}
