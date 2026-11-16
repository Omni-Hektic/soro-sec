use crate::model::{ScanReport, Severity};
use anyhow::Result;
use colored::*;

pub fn render(report: &ScanReport) -> Result<String> {
    let mut out = String::new();

    out.push_str(&format!(
        "\n{}\n",
        "=== soro-sec: Soroban Smart Contract Security Scanner ==="
            .bold()
            .cyan()
    ));
    out.push_str(&format!(
        "Target: {} | Files Scanned: {} | Scan Time: {}ms\n\n",
        report.target_path, report.summary.total_files, report.duration_ms
    ));

    if report.findings.is_empty() {
        out.push_str(&format!(
            "{}\n\n",
            "✔ No security vulnerabilities or policy violations detected!".green().bold()
        ));
        return Ok(out);
    }

    for (idx, f) in report.findings.iter().enumerate() {
        let badge = match f.severity {
            Severity::Critical => "[CRITICAL]".on_red().white().bold(),
            Severity::High => "[HIGH]".red().bold(),
            Severity::Medium => "[MEDIUM]".yellow().bold(),
            Severity::Low => "[LOW]".blue().bold(),
            Severity::Informational => "[INFO]".white().dimmed(),
        };

        out.push_str(&format!(
            "{}. {} {}: {}\n",
            idx + 1,
            badge,
            f.rule_id.bold(),
            f.title.bold()
        ));
        out.push_str(&format!(
            "   Location: {}:{}:{}\n",
            f.file_path.underline(),
            f.line,
            f.column
        ));
        out.push_str(&format!("   Message:  {}\n", f.message));

        if !f.snippet.is_empty() {
            out.push_str(&format!(
                "   Snippet:  {}\n",
                f.snippet.dimmed()
            ));
        }

        out.push_str(&format!(
            "   Fix:      {}\n\n",
            f.remediation.green()
        ));
    }

    out.push_str("--------------------------------------------------\n");
    out.push_str(&format!(
        "Summary: {} critical, {} high, {} medium, {} low, {} info\n",
        report.summary.critical_count.to_string().red().bold(),
        report.summary.high_count.to_string().red(),
        report.summary.medium_count.to_string().yellow(),
        report.summary.low_count.to_string().blue(),
        report.summary.info_count
    ));

    Ok(out)
}
