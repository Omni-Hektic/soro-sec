use crate::model::ScanReport;
use anyhow::Result;

pub fn render(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
