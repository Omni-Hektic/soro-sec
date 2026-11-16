use crate::model::{Finding, ScanReport, SecurityRule};
use crate::rules::default_ruleset;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

pub struct ScannerEngine {
    rules: Vec<Arc<dyn SecurityRule>>,
    target_path: PathBuf,
}

impl ScannerEngine {
    pub fn new(target_path: PathBuf) -> Self {
        Self {
            rules: default_ruleset(),
            target_path,
        }
    }

    pub fn with_rules(mut self, rules: Vec<Arc<dyn SecurityRule>>) -> Self {
        self.rules = rules;
        self
    }

    pub fn scan(&self) -> Result<ScanReport> {
        let start = Instant::now();
        let mut total_files = 0;
        let mut all_findings: Vec<Finding> = Vec::new();

        let files = self.collect_rust_files(&self.target_path);

        for file_path in &files {
            total_files += 1;
            if let Ok(content) = fs::read_to_string(file_path) {
                // Try parsing AST, continue with None if syntax contains custom macros syn doesn't fully understand
                let ast = syn::parse_file(&content).ok();

                for rule in &self.rules {
                    let mut findings = rule.check(file_path, &content, ast.as_ref());
                    all_findings.append(&mut findings);
                }
            }
        }

        let duration_ms = start.elapsed().as_millis();
        Ok(ScanReport::new(
            self.target_path.display().to_string(),
            total_files,
            duration_ms,
            all_findings,
        ))
    }

    fn collect_rust_files(&self, root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();

        if root.is_file() {
            if root.extension().map_or(false, |ext| ext == "rs") {
                files.push(root.to_path_buf());
            }
            return files;
        }

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                // Exclude target and hidden directories
                name != "target" && !name.starts_with('.')
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "rs") {
                files.push(path.to_path_buf());
            }
        }

        files
    }
}
