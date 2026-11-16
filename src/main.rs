use anyhow::Result;
use clap::Parser;
use colored::*;
use soro_sec::engine::ScannerEngine;
use soro_sec::model::Severity;
use soro_sec::reporters::{render_report, ReportFormat};
use soro_sec::rules::default_ruleset;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(
    name = "soro-sec",
    author = "Omni-Hektic <admin@digital-pathways.net>",
    version,
    about = "Static security analysis & vulnerability linter for Soroban smart contracts on Stellar",
    long_about = "soro-sec inspects Soroban Rust smart contract codebases to detect storage TTL expiration traps, missing require_auth() checks, Checks-Effects-Interactions (CEI) violations, unchecked financial arithmetic, and storage key collisions."
)]
struct Cli {
    /// Path to a Soroban contract directory or .rs file
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output report format: terminal, json, sarif, markdown
    #[arg(short, long, default_value = "terminal")]
    format: String,

    /// Optional path to save the scan report to disk
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Fail with exit code 1 if findings meet or exceed this severity (CRITICAL, HIGH, MEDIUM, LOW)
    #[arg(long)]
    fail_on: Option<String>,

    /// List all registered security rules and exit
    #[arg(long)]
    list_rules: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_rules {
        println!("\n{}", "=== soro-sec: Active Detection Rules ===".bold().cyan());
        let rules = default_ruleset();
        for r in rules {
            println!(
                "• [{}] {} - [{}]\n  {}\n",
                r.id().bold().yellow(),
                r.name().bold(),
                r.severity().to_string().red(),
                r.description().dimmed()
            );
        }
        return Ok(());
    }

    let format = ReportFormat::from_str(&cli.format)
        .map_err(|e| anyhow::anyhow!(e))?;

    let engine = ScannerEngine::new(cli.path);
    let report = engine.scan()?;

    let rendered = render_report(&report, format)?;

    if let Some(ref out_path) = cli.output {
        fs::write(out_path, &rendered)?;
        println!("Report saved to: {}", out_path.display());
    } else {
        print!("{}", rendered);
    }

    if let Some(ref threshold_str) = cli.fail_on {
        let threshold = Severity::from_str(threshold_str)
            .map_err(|e| anyhow::anyhow!(e))?;

        if report.has_failures_above(threshold) {
            eprintln!(
                "{}: Findings detected meeting or exceeding severity threshold '{}'.",
                "FAILED".red().bold(),
                threshold
            );
            process::exit(1);
        }
    }

    Ok(())
}
