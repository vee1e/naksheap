//! naksheap-viz
//!
//! Visualization of the naksheap object graph: a root-anchored ASCII tree,
//! Graphviz DOT, and an HTML/cytoscape report (graph JSON embedded, cytoscape.js
//! loaded from a CDN).

pub mod ascii;
pub mod dot;
pub mod html;

pub use ascii::ascii_tree;
pub use dot::to_dot;
pub use html::to_html;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use naksheap_allocator_heuristics::carve;
    use naksheap_core_parse::elf::parse_elf_bytes;
    use naksheap_core_parse::MappedImage;
    use naksheap_inference::{Node, ObjectGraph};
    use naksheap_pointer_scan::{scan, ScanOptions};

    use super::*;

    /// Builds the fixture and runs the full pipeline, returning the object
    /// graph plus the ground-truth fixture for address assertions.
    fn fixture_graph() -> (ObjectGraph, naksheap_testkit::Fixture) {
        let fixture = naksheap_testkit::CoreSpec::default()
            .build()
            .expect("fixture build");
        let parsed = parse_elf_bytes(&fixture.bytes).expect("parse fixture core");
        let image = MappedImage::from_bytes(
            fixture.bytes.clone(),
            parsed.map.clone(),
            parsed.pointer_width,
        );
        let inventory = carve(&image);
        let scan = scan(&image, &inventory, &parsed.threads, &ScanOptions::default());
        let graph = naksheap_inference::build_graph(&image, &inventory, &scan);
        (graph, fixture)
    }

    #[test]
    fn ascii_tree_contains_fields_and_children() {
        let (graph, fixture) = fixture_graph();
        let tree = ascii_tree(&graph, 8);

        assert!(tree.contains("naksheap object graph"), "tree: {tree}");
        assert!(tree.contains("probable struct"), "tree: {tree}");
        assert!(tree.contains("+0x00 pointer"), "tree: {tree}");
        assert!(tree.contains("[root]"), "tree: {tree}");
        assert!(tree.contains("(see above)"), "cycle dedup marker missing: {tree}");

        let unreachable: Vec<&Node> = graph
            .nodes
            .iter()
            .filter(|n| !n.reachable_from_root && !n.is_root)
            .collect();
        assert!(
            !unreachable.is_empty(),
            "fixture should contain objects unreachable from roots"
        );
        assert!(tree.contains("unreachable"), "unreachable section missing: {tree}");
        for n in unreachable {
            assert!(
                tree.contains(&format!("0x{:x}", n.addr)),
                "unreachable address 0x{:x} missing from tree:\n{tree}",
                n.addr
            );
        }

        let roots: Vec<u64> = graph
            .nodes
            .iter()
            .filter(|n| n.is_root)
            .map(|n| n.addr)
            .collect();
        assert!(!roots.is_empty(), "fixture should produce root nodes");

        let mut reachable: HashSet<u64> = roots.iter().copied().collect();
        loop {
            let before = reachable.len();
            for e in &graph.edges {
                if reachable.contains(&e.from) && e.from != 0 {
                    reachable.insert(e.to);
                }
            }
            if reachable.len() == before {
                break;
            }
        }
        for addr in reachable {
            assert!(
                tree.contains(&format!("0x{addr:x}")),
                "reachable child address 0x{addr:x} missing from tree:\n{tree}"
            );
        }
        assert!(tree.contains(&format!("0x{:x}", fixture.manifest.objects[1].addr)));
    }

    #[test]
    fn dot_output_starts_with_digraph() {
        let (graph, _fixture) = fixture_graph();
        let dot = to_dot(&graph);
        assert!(dot.starts_with("digraph"), "dot: {dot}");
        assert!(dot.contains("->"), "dot: {dot}");
        assert!(dot.contains("0x"), "dot: {dot}");
    }

    #[test]
    fn html_contains_embedded_json() {
        let (graph, fixture) = fixture_graph();
        let html = to_html(&graph);
        assert!(html.contains("cytoscape"), "html: {html}");
        assert!(html.contains("stats"), "html: {html}");
        assert!(
            html.contains(&format!("0x{:x}", fixture.manifest.objects[0].addr)),
            "html: {html}"
        );
        let data_line = html
            .lines()
            .find(|l| l.trim_start().starts_with("const DATA = "))
            .expect("DATA line");
        let data = data_line.trim_start().trim_start_matches("const DATA = ");
        assert!(
            !data.contains("</"),
            "embedded JSON contains an unescaped </ (would close the script tag)"
        );
    }
}
