use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Informational => "INFO",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Ok(Severity::Critical),
            "HIGH" => Ok(Severity::High),
            "MEDIUM" => Ok(Severity::Medium),
            "LOW" => Ok(Severity::Low),
            "INFO" | "INFORMATIONAL" => Ok(Severity::Informational),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub snippet: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_files: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target_path: String,
    pub duration_ms: u128,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(target_path: String, total_files: usize, duration_ms: u128, findings: Vec<Finding>) -> Self {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for f in &findings {
            match f.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                Severity::Informational => info_count += 1,
            }
        }

        Self {
            target_path,
            duration_ms,
            summary: ScanSummary {
                total_files,
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count,
            },
            findings,
        }
    }

    pub fn has_failures_above(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= threshold)
    }
}

pub trait SecurityRule: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn description(&self) -> &'static str;
    fn check(&self, path: &Path, content: &str, ast: Option<&syn::File>) -> Vec<Finding>;
}
