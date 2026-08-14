//! naksheap-cli: parse, carve, scan, infer, and visualize heap object graphs
//! from core dumps.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use naksheap_allocator_heuristics::{carve, ObjectState};
use naksheap_core_parse::{open, AddressSpace, CoreFile, CoreFormat, Perms, RangeKind};

#[derive(Parser)]
#[command(name = "naksheap", version, about = "heap archaeology for stripped binaries")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a core dump: format, process, threads, memory map.
    Info { core: PathBuf },
    /// Print the memory map (ranges, permissions, heap markers).
    Maps { core: PathBuf },
    /// Carve the heap and print the object inventory.
    Heap { core: PathBuf },
    /// Build the object graph and export it (ascii tree / dot / html / json).
    Graph {
        core: PathBuf,
        /// Maximum recursion depth for the ASCII tree.
        #[arg(long, default_value_t = 8)]
        max_depth: usize,
        /// Emit Graphviz DOT (stdout, or --out/graph.dot).
        #[arg(long)]
        dot: bool,
        /// Write an HTML report (--out/report.html; embeds the graph JSON,
        /// loads cytoscape.js from a CDN).
        #[arg(long)]
        html: bool,
        /// Emit graph JSON (stdout, or --out/graph.json).
        #[arg(long)]
        json: bool,
        /// Output directory for file exports.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// Run the full pipeline on a synthetic fixture (smoke test).
    SelfTest,
}

fn main() {
    // Piping output into a consumer that closes early (e.g. `naksheap graph
    // core | head`) raises SIGPIPE on the write. Rust converts that into an
    // `io::ErrorKind::BrokenPipe` and `println!` panics; a CLI must instead
    // terminate quietly, and because the consumer intentionally stopped
    // reading (not an error), exit 0 rather than the conventional 141 so
    // `set -o pipefail` scripts don't treat it as a failure.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.starts_with("failed printing to ") && msg.contains("Broken pipe") {
            std::process::exit(0);
        }
        default_hook(info);
    }));

    if let Err(err) = run() {
        // `err` is already a single, fully-formatted message (e.g. a
        // `naksheap_core_parse::Error` whose display embeds the OS error).
        // Printing with `{}` avoids anyhow's source chain, so the OS message
        // appears exactly once.
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { core } => cmd_info(&core),
        Command::Maps { core } => cmd_maps(&core),
        Command::Heap { core } => cmd_heap(&core),
        Command::Graph {
            core,
            max_depth,
            dot,
            html,
            json,
            out,
        } => cmd_graph(&core, max_depth, dot, html, json, out.as_deref()),
        Command::SelfTest => cmd_self_test(),
    }
}

/// Warns (once) when the dump is a truncated snapshot: memory ranges extend
/// past the end of the file, so carved results are silently partial.
fn warn_truncated(core: &naksheap_core_parse::CoreFile) {
    if core.image.is_truncated() {
        eprintln!(
            "warning: core file appears truncated (memory ranges extend past the \
             end of the file); results may be incomplete"
        );
    }
}

fn cmd_info(path: &Path) -> Result<()> {
    let core = open(path)?;
    warn_truncated(&core);

    println!("format: {}", format_name(core.format));
    println!("process: {}", core.process_name.as_deref().unwrap_or("?"));
    println!("command line: {}", core.command_line.as_deref().unwrap_or("?"));
    println!("exec path: {}", core.exec_path.as_deref().unwrap_or("?"));
    println!("pointer width: {} bytes", core.image.pointer_width());
    println!("threads: {}", core.threads.len());
    print_maps(&core);
    Ok(())
}

fn cmd_maps(path: &Path) -> Result<()> {
    let core = open(path)?;
    print_maps(&core);
    Ok(())
}

/// Prints the memory map: ranges, permissions, kind, and the ranges that
/// contain a detected arena's `top` marked `[heap]`.
fn print_maps(core: &CoreFile) {
    let heaps = heap_range_starts(core);
    println!(
        "memory map ({} ranges, {} bytes total):",
        core.maps.len(),
        core.maps.total_bytes()
    );
    for r in core.maps.iter() {
        let name = if heaps.contains(&r.start) {
            "[heap]".to_string()
        } else {
            r.name.clone().unwrap_or_else(|| "?".to_string())
        };
        println!(
            "  {:#018x}-{:#018x} {} {} {}",
            r.start,
            r.end,
            perms_str(&r.perms),
            kind_str(r.kind),
            name
        );
    }
}

/// Starts of map ranges that contain a detected arena's `top` (the heap).
fn heap_range_starts(core: &CoreFile) -> HashSet<u64> {
    let inventory = carve(&core.image);
    inventory
        .arenas
        .iter()
        .filter_map(|a| core.maps.range_at(a.top).map(|r| r.start))
        .collect()
}

fn cmd_heap(path: &Path) -> Result<()> {
    let core = open(path)?;
    warn_truncated(&core);
    let inventory = carve(&core.image);
    let scan = naksheap_pointer_scan::scan(
        &core.image,
        &inventory,
        &core.threads,
        &naksheap_pointer_scan::ScanOptions::default(),
    );

    println!("arenas ({}):", inventory.arenas.len());
    for a in &inventory.arenas {
        println!(
            "  0x{:x}  top=0x{:x}  size=0x{:x}  main={}",
            a.addr, a.top, a.size, a.is_main
        );
    }

    let mut objects = inventory.objects.clone();
    objects.sort_by_key(|o| o.addr);
    println!("objects ({}):", objects.len());
    println!("  {:<18} {:>10}  {:<10}  arena", "addr", "size", "state");
    for o in &objects {
        let arena = o.arena.map(|a| format!("0x{a:x}")).unwrap_or_else(|| "-".into());
        println!("  0x{:x}  {:#010x}  {:<10}  {}", o.addr, o.size, state_str(o.state), arena);
    }

    let allocated = objects.iter().filter(|o| o.state == ObjectState::Allocated).count();
    let freed = objects.iter().filter(|o| o.state == ObjectState::Freed).count();
    let mmap = objects.iter().filter(|o| o.state == ObjectState::Mmap).count();
    let unknown = objects.len() - allocated - freed - mmap;
    println!(
        "counts: {} total, {} allocated, {} freed, {} mmap, {} unknown; {} stray pointers",
        objects.len(),
        allocated,
        freed,
        mmap,
        unknown,
        scan.stray_pointers.len()
    );
    Ok(())
}

fn cmd_graph(
    path: &Path,
    max_depth: usize,
    want_dot: bool,
    want_html: bool,
    want_json: bool,
    out: Option<&Path>,
) -> Result<()> {
    let core = open(path)?;
    warn_truncated(&core);
    let inventory = carve(&core.image);
    let scan = naksheap_pointer_scan::scan(
        &core.image,
        &inventory,
        &core.threads,
        &naksheap_pointer_scan::ScanOptions::default(),
    );
    let graph = naksheap_inference::build_graph(&core.image, &inventory, &scan);

    if want_html {
        let dir = out.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("naksheap-report"));
        std::fs::create_dir_all(&dir).context("failed to create output dir")?;
        let html = naksheap_viz::to_html(&graph);
        std::fs::write(dir.join("report.html"), html).context("failed to write report.html")?;
        println!("wrote {}", dir.join("report.html").display());
    }
    if want_dot {
        let dot = naksheap_viz::to_dot(&graph);
        match out {
            Some(dir) => {
                std::fs::create_dir_all(dir).context("failed to create output dir")?;
                std::fs::write(dir.join("graph.dot"), dot).context("failed to write graph.dot")?;
                println!("wrote {}", dir.join("graph.dot").display());
            }
            None => print!("{dot}"),
        }
    }
    if want_json {
        let value = naksheap_inference::graph_to_json(&graph);
        let json = serde_json::to_string_pretty(&value).context("failed to serialize graph JSON")?;
        match out {
            Some(dir) => {
                std::fs::create_dir_all(dir).context("failed to create output dir")?;
                std::fs::write(dir.join("graph.json"), json).context("failed to write graph.json")?;
                println!("wrote {}", dir.join("graph.json").display());
            }
            None => println!("{json}"),
        }
    }
    if !want_dot && !want_html && !want_json {
        println!("{}", naksheap_viz::ascii_tree(&graph, max_depth));
    }
    Ok(())
}

fn cmd_self_test() -> Result<()> {
    let spec = naksheap_testkit::CoreSpec::default();
    let fixture = spec.build().context("failed to build self-test fixture")?;
    let parsed =
        naksheap_core_parse::elf::parse_elf_bytes(&fixture.bytes).context("failed to parse fixture")?;
    let image = naksheap_core_parse::MappedImage::from_bytes(
        fixture.bytes.clone(),
        parsed.map.clone(),
        parsed.pointer_width,
    );
    let inventory = carve(&image);
    let scan = naksheap_pointer_scan::scan(
        &image,
        &inventory,
        &parsed.threads,
        &naksheap_pointer_scan::ScanOptions::default(),
    );
    let graph = naksheap_inference::build_graph(&image, &inventory, &scan);

    println!("naksheap self-test");
    println!(
        "  parse: ok (format={}, {} threads, pointer width {} bytes)",
        format_name(parsed.format),
        parsed.threads.len(),
        parsed.pointer_width
    );
    println!(
        "  carve: {} objects, {} arenas",
        inventory.objects.len(),
        inventory.arenas.len()
    );
    println!(
        "  scan:  {} edges, {} roots, {} stray pointers",
        scan.edges.len(),
        scan.roots.len(),
        scan.stray_pointers.len()
    );
    println!(
        "  graph: {} nodes, {} edges, {} root-reachable",
        graph.nodes.len(),
        graph.edges.len(),
        graph.stats.root_reachable
    );

    let mut missing: Vec<&str> = Vec::new();
    for m in &fixture.manifest.objects {
        if !inventory.objects.iter().any(|o| o.addr == m.addr) {
            missing.push(m.label.as_str());
        }
    }
    if !missing.is_empty() {
        bail!(
            "self-test failed: {} manifest objects missing from carve: {:?}",
            missing.len(),
            missing
        );
    }
    println!(
        "  fidelity: all {} manifest objects recovered",
        fixture.manifest.objects.len()
    );
    println!("self-test OK");
    Ok(())
}

fn format_name(format: CoreFormat) -> &'static str {
    match format {
        CoreFormat::Elf64 => "elf64",
        CoreFormat::Elf32 => "elf32",
        CoreFormat::Minidump => "minidump",
    }
}

fn perms_str(p: &Perms) -> String {
    let mut s = String::with_capacity(3);
    s.push(if p.read { 'r' } else { '-' });
    s.push(if p.write { 'w' } else { '-' });
    s.push(if p.execute { 'x' } else { '-' });
    s
}

fn kind_str(k: RangeKind) -> &'static str {
    match k {
        RangeKind::File => "file",
        RangeKind::Anon => "anon",
        RangeKind::Unknown => "unknown",
    }
}

fn state_str(s: ObjectState) -> &'static str {
    match s {
        ObjectState::Allocated => "allocated",
        ObjectState::Freed => "freed",
        ObjectState::Mmap => "mmap",
        ObjectState::Unknown => "unknown",
    }
}
