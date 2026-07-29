use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    events::{EventHandler, EventName},
    mast::MastForest,
};

use crate::{Package, PackageDebugInfoError, debug_info::PackageDebugInfo};

/// A rich library representing a [`MastForest`] which also exports a list of handlers for events it
/// may call.
pub struct HostLibrary {
    /// A [`MastForest`] with procedures exposed by this library.
    pub mast_forest: Arc<MastForest>,
    /// Package-owned debug info that belongs to `mast_forest`.
    pub package_debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
    /// List of handlers along with their event names to call them with `emit`.
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
}

impl Default for HostLibrary {
    fn default() -> Self {
        Self {
            mast_forest: Arc::new(MastForest::new()),
            package_debug_info: Ok(None),
            handlers: Vec::new(),
        }
    }
}

impl From<Arc<Package>> for HostLibrary {
    fn from(package: Arc<Package>) -> Self {
        let package_debug_info = match package.debug_info() {
            Ok(debug_info) => Ok(debug_info),
            Err(PackageDebugInfoError::UntrustedSections) => Ok(None),
            Err(err) => Err(err),
        };

        Self {
            mast_forest: package.mast_forest().clone(),
            package_debug_info,
            handlers: Vec::new(),
        }
    }
}

impl From<Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: Arc<MastForest>) -> Self {
        Self {
            mast_forest,
            package_debug_info: Ok(None),
            handlers: Vec::new(),
        }
    }
}

impl From<&Arc<MastForest>> for HostLibrary {
    fn from(mast_forest: &Arc<MastForest>) -> Self {
        Self {
            mast_forest: mast_forest.clone(),
            package_debug_info: Ok(None),
            handlers: Vec::new(),
        }
    }
}
