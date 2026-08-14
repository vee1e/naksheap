//! naksheap-testkit
//!
//! Deterministic synthetic fixture generation for naksheap.
//!
//! [`CoreSpec`] declaratively describes a 64-bit Linux/glibc core dump; its
//! [`CoreSpec::build`] materializes it into a [`Fixture`]: byte-for-byte
//! reproducible ELF64 core bytes plus a ground-truth [`Manifest`] of arenas,
//! carved heap objects, roots, and pointer edges. Downstream crates and tests
//! assert their reconstruction *fidelity* against the manifest, not just that
//! they "ran".
//!
//! ```
//! use naksheap_testkit::{CoreSpec, Fixture};
//!
//! let spec = CoreSpec::default();
//! let fixture = Fixture::from_spec(&spec)?;
//! // fixture.bytes   -> synthetic ELF64 core
//! // fixture.manifest-> ground truth (arenas, objects, roots, edges)
//! # Ok::<(), naksheap_testkit::BuilderError>(())
//! ```

pub mod build;
pub mod error;
pub mod manifest;
pub mod spec;

use std::io::Write;
use std::path::Path;

pub use error::{BuilderError, Result};
pub use manifest::{
    EdgeKind, Manifest, ManifestArena, ManifestEdge, ManifestObject, ManifestRoot, ObjectState,
    RootKind,
};
pub use spec::{CoreSpec, PointerField, SpecObject, SpecRoot, SpecState, Target};

/// A built fixture: the synthetic core bytes plus the ground-truth manifest
/// describing what a correct heap-analysis pipeline must recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    /// The complete synthetic ELF64 core dump.
    pub bytes: Vec<u8>,
    /// Ground truth for the fixture.
    pub manifest: Manifest,
}

impl Fixture {
    /// Builds a fixture from `spec`, validating the spec and producing
    /// deterministic output.
    pub fn from_spec(spec: &CoreSpec) -> Result<Fixture> {
        let (bytes, manifest) = build::build_spec(spec)?;
        Ok(Fixture { bytes, manifest })
    }

    /// Writes the core dump to `path`.
    pub fn write(&self, path: &Path) -> Result<()> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(&self.bytes)?;
        Ok(())
    }

    /// Renders the ground-truth manifest as indented JSON.
    pub fn manifest_json(&self) -> Result<String> {
        Ok(self.manifest.to_json()?)
    }

    /// Writes the manifest JSON next to `core_path` with a `.manifest.json`
    /// suffix.
    pub fn write_manifest(&self, core_path: &Path) -> Result<()> {
        let json = self.manifest_json()?;
        let mut path = core_path.as_os_str().to_owned();
        path.push(".manifest.json");
        let mut f = std::fs::File::create(&path)?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(())
    }
}

impl CoreSpec {
    /// Builds a fixture from this spec.
    pub fn build(&self) -> Result<Fixture> {
        Fixture::from_spec(self)
    }
}
