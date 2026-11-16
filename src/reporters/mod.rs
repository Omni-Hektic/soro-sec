pub mod json;
pub mod markdown;
pub mod sarif;
pub mod terminal;

use crate::model::ScanReport;
use anyhow::Result;

pub enum ReportFormat {
    Terminal,
    Json,
    Sarif,
    Markdown,
}

impl std::str::FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "terminal" | "text" => Ok(ReportFormat::Terminal),
            "json" => Ok(ReportFormat::Json),
            "sarif" => Ok(ReportFormat::Sarif),
            "markdown" | "md" => Ok(ReportFormat::Markdown),
            _ => Err(format!("Unknown format '{}'. Supported: terminal, json, sarif, markdown", s)),
        }
    }
}

pub fn render_report(report: &ScanReport, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Terminal => terminal::render(report),
        ReportFormat::Json => json::render(report),
        ReportFormat::Sarif => sarif::render(report),
        ReportFormat::Markdown => markdown::render(report),
    }
}
