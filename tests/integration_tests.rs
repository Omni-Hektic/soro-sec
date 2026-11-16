use soro_sec::engine::ScannerEngine;
use std::path::PathBuf;

#[test]
fn test_detects_vulnerabilities_in_vulnerable_fixture() {
    let fixture_path = PathBuf::from("tests/fixtures/vulnerable_contract.rs");
    let engine = ScannerEngine::new(fixture_path);
    let report = engine.scan().expect("Failed to scan fixture");

    println!("Detected findings: {:#?}", report.findings);
    assert!(!report.findings.is_empty(), "Expected findings in vulnerable fixture");

    let rule_ids: Vec<String> = report.findings.iter().map(|f| f.rule_id.clone()).collect();

    assert!(rule_ids.contains(&"SG001".to_string()), "Expected SG001 (TTL), found: {:?}", rule_ids);
    assert!(rule_ids.contains(&"SG002".to_string()), "Expected SG002 (Missing Auth), found: {:?}", rule_ids);
    assert!(rule_ids.contains(&"SG003".to_string()), "Expected SG003 (CEI Violation), found: {:?}", rule_ids);
    assert!(rule_ids.contains(&"SG004".to_string()), "Expected SG004 (Unchecked Math), found: {:?}", rule_ids);
    assert!(rule_ids.contains(&"SG005".to_string()), "Expected SG005 (Storage Collision), found: {:?}", rule_ids);
}

#[test]
fn test_clean_scan_on_secure_fixture() {
    let fixture_path = PathBuf::from("tests/fixtures/secure_contract.rs");
    let engine = ScannerEngine::new(fixture_path);
    let report = engine.scan().expect("Failed to scan fixture");

    assert!(
        report.findings.is_empty(),
        "Expected zero findings in secure fixture, got: {:?}",
        report.findings
    );
}
