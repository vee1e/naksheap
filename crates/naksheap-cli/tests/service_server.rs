//! Runs the Python HTTP tests for deploy/server.py as part of `cargo test`.
//!
//! The GitHub workflow already executes `cargo test --workspace`, so this is
//! how those service tests stay on the CI path without a new workflow file.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/naksheap-cli -> repo root
    dir.pop();
    dir.pop();
    dir
}

#[test]
fn deploy_server_python_tests() {
    let root = workspace_root();
    let status = Command::new("python3")
        .args([
            "-m",
            "unittest",
            "discover",
            "-s",
            "deploy",
            "-p",
            "test_*.py",
            "-v",
        ])
        .current_dir(&root)
        .status()
        .expect("failed to spawn python3");
    assert!(
        status.success(),
        "deploy/test_server.py failed (cwd {})",
        root.display()
    );
}
