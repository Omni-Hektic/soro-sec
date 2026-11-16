pub mod sg001_ttl_extension;
pub mod sg002_missing_auth;
pub mod sg003_cei_violation;
pub mod sg004_unchecked_math;
pub mod sg005_storage_collision;

use crate::model::SecurityRule;
use std::sync::Arc;

pub fn default_ruleset() -> Vec<Arc<dyn SecurityRule>> {
    vec![
        Arc::new(sg001_ttl_extension::MissingTtlExtensionRule),
        Arc::new(sg002_missing_auth::MissingRequireAuthRule),
        Arc::new(sg003_cei_violation::CeiViolationRule),
        Arc::new(sg004_unchecked_math::UncheckedMathRule),
        Arc::new(sg005_storage_collision::StorageCollisionRule),
    ]
}
