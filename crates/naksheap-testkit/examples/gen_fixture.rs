//! Generates a fixture core dump + ground-truth manifest for manual testing.
//!
//! Usage: `cargo run -p naksheap-testkit --example gen_fixture -- <out-dir>`

use naksheap_testkit::CoreSpec;

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/naksheap-fixtures".to_string());
    let dir = std::path::Path::new(&out);
    std::fs::create_dir_all(dir).expect("create out dir");

    let spec = CoreSpec::default();
    let fixture = spec.build().expect("build fixture");
    let core = dir.join("toy-server.core");
    fixture.write(&core).expect("write core");
    fixture.write_manifest(&core).expect("write manifest");
    println!("wrote {}", core.display());
}
