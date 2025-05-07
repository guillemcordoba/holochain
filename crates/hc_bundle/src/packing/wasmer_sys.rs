use crate::error::HcBundleError;
use holochain_util::ffs;
use mr_bundle::{Bundle, Manifest};
use std::path::Path;
use tracing::info;

/// DEPRECATED: Bundling precompiled and preserialized wasm for iOS is deprecated. Please use the wasm interpreter instead.
pub(super) async fn build_preserialized_wasm<M: Manifest>(
    target_path: &Path,
    bundle: &Bundle<M>,
) -> Result<(), HcBundleError> {
    let target_path_folder = target_path
        .parent()
        .expect("target_path should have a parent folder");

    Ok(())
}
