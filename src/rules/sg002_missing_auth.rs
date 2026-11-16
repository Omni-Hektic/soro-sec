use crate::model::{Finding, SecurityRule, Severity};
use std::path::Path;
use syn::visit::Visit;
use syn::ItemImpl;

pub struct MissingRequireAuthRule;

impl SecurityRule for MissingRequireAuthRule {
    fn id(&self) -> &'static str {
        "SG002"
    }

    fn name(&self) -> &'static str {
        "Missing require_auth() on Privileged Action"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn description(&self) -> &'static str {
        "Public contract functions performing state mutation or privileged operations must call address.require_auth(). Missing auth checks allow arbitrary callers to execute privileged actions."
    }

    fn check(&self, path: &Path, content: &str, ast: Option<&syn::File>) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(file_ast) = ast {
            struct ContractImplVisitor<'a> {
                rule_id: String,
                title: String,
                severity: Severity,
                file_path: String,
                findings: Vec<Finding>,
                source_lines: Vec<&'a str>,
            }

            impl<'ast, 'a> Visit<'ast> for ContractImplVisitor<'a> {
                fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
                    // Check if impl has #[contractimpl] attribute
                    let is_contract_impl = node.attrs.iter().any(|attr| {
                        attr.path().is_ident("contractimpl")
                    });

                    if is_contract_impl {
                        for item in &node.items {
                            if let syn::ImplItem::Fn(method) = item {
                                self.check_method(method);
                            }
                        }
                    }

                    syn::visit::visit_item_impl(self, node);
                }
            }

            impl<'a> ContractImplVisitor<'a> {
                fn check_method(&mut self, method: &syn::ImplItemFn) {
                    let fn_name = method.sig.ident.to_string();

                    // Check if function name matches high-risk sensitive actions
                    let is_sensitive_name = fn_name.contains("admin")
                        || fn_name.contains("upgrade")
                        || fn_name.contains("transfer_ownership")
                        || fn_name.contains("withdraw")
                        || fn_name.contains("set_")
                        || fn_name.contains("pause")
                        || fn_name.contains("mint")
                        || fn_name.contains("claim");

                    // Check parameters for Address types
                    let mut address_params = Vec::new();
                    for input in &method.sig.inputs {
                        if let syn::FnArg::Typed(pat_type) = input {
                            let type_str = quote::quote!(#pat_type).to_string();
                            if type_str.contains("Address") {
                                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                                    address_params.push(pat_ident.ident.to_string());
                                }
                            }
                        }
                    }

                    if is_sensitive_name || !address_params.is_empty() {
                        let body_str = quote::quote!(#method).to_string();
                        let has_require_auth = body_str.contains("require_auth");

                        if !has_require_auth {
                            let line = method.sig.ident.span().start().line;
                            let snippet = self.source_lines.get(line.saturating_sub(1))
                                .unwrap_or(&"")
                                .trim()
                                .to_string();

                            self.findings.push(Finding {
                                rule_id: self.rule_id.clone(),
                                title: self.title.clone(),
                                severity: self.severity,
                                file_path: self.file_path.clone(),
                                line,
                                column: 1,
                                message: format!(
                                    "Function `{}` performs sensitive or parameterized operations without validating caller authorization via require_auth().",
                                    fn_name
                                ),
                                snippet,
                                remediation: "Add `address.require_auth()` at the beginning of the function body to verify caller permissions.".to_string(),
                            });
                        }
                    }
                }
            }

            let source_lines = content.lines().collect();
            let mut visitor = ContractImplVisitor {
                rule_id: self.id().to_string(),
                title: self.name().to_string(),
                severity: self.severity(),
                file_path: path.display().to_string(),
                findings: Vec::new(),
                source_lines,
            };

            visitor.visit_file(file_ast);
            findings.extend(visitor.findings);
        } else {
            // Regex fallback if AST fails
            for (line_idx, line) in content.lines().enumerate() {
                if (line.contains("fn set_admin") || line.contains("fn upgrade") || line.contains("fn transfer_ownership"))
                    && !content.contains("require_auth")
                {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        title: self.name().to_string(),
                        severity: self.severity(),
                        file_path: path.display().to_string(),
                        line: line_idx + 1,
                        column: 1,
                        message: "Privileged function detected without require_auth() validation.".to_string(),
                        snippet: line.trim().to_string(),
                        remediation: "Add caller authorization check `admin.require_auth()`.".to_string(),
                    });
                }
            }
        }

        findings
    }
}
