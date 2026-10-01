//! naksheap-wasm
//!
//! WebAssembly bindings for naksheap. Runs the full analysis pipeline
//! (parse -> carve -> pointer scan -> inference) on a core dump entirely in
//! the browser: the dump bytes are read from a `<input type=file>` or a drag
//! drop, never uploaded, never written to disk.
//!
//! # Why this does not use the CLI
//!
//! The analysis is expressed entirely in terms of the library crates. This
//! crate depends on those five crates and *not* on `naksheap-cli`, so nothing
//! here pulls in `std::fs`, `std::process`, or `clap`. The only entry point
//! that needs a filesystem is `naksheap_core_parse::open`, which takes a
//! `Path`; instead this crate uses the in-memory path
//! (`parse_elf_bytes` + `MappedImage::from_bytes`) that `naksheap self-test`
//! already exercises.
//!
//! # Memory ceiling
//!
//! `wasm32` linear memory is capped at 4 GiB, and the pipeline's peak
//! footprint is roughly 5-6x the input size, plus a similar multiple again to
//! serialize the result. That puts the practical ceiling for a single browser
//! analysis at a few hundred MiB of dump, far below what the native CLI or the
//! Docker service can take. Callers should check
//! [`MAX_INPUT_BYTES`] before starting and fall back to the service for
//! larger dumps. See `deployment.md`.

use std::sync::atomic::{AtomicU8, Ordering};

use naksheap_allocator_heuristics::carve;
use naksheap_core_parse::{CoreFile, CoreFormat, MappedImage};
use naksheap_pointer_scan::{scan_with_progress, ScanOptions};
use serde_json::json;
use wasm_bindgen::prelude::*;

/// Largest dump this build will attempt, in bytes.
///
/// A `wasm32` guest cannot address more than 4 GiB of linear memory, and the
/// pipeline needs several times the input size to work plus to serialize. This
/// cap is a guard against a browser tab dying mid-analysis, not a promise that
/// every dump under it will succeed: a pathological dump can still exhaust
/// memory, and the caller must handle that failure.
pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;

/// A pipeline stage, so the UI can say what is happening rather than showing an
/// indeterminate spinner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Reading and decoding the ELF core headers and notes.
    Parse,
    /// Walking glibc chunk headers to find heap objects.
    Carve,
    /// Scanning object payloads and thread stacks for pointers.
    Scan,
    /// Inferring types, clustering layouts, building the graph.
    Infer,
    /// Serializing the result to JSON for the UI.
    Serialize,
}

impl Stage {
    /// Coarse stage index, for computing an overall fraction.
    fn index(self) -> usize {
        match self {
            Stage::Parse => 0,
            Stage::Carve => 1,
            Stage::Scan => 2,
            Stage::Infer => 3,
            Stage::Serialize => 4,
        }
    }

    /// Weight of each stage in the overall progress fraction. Carve and scan
    /// dominate real run time, so they get most of the bar; parse, infer, and
    /// serialize are comparatively quick.
    fn weight(self) -> f32 {
        match self {
            Stage::Parse => 0.05,
            Stage::Carve => 0.15,
            Stage::Scan => 0.6,
            Stage::Infer => 0.15,
            Stage::Serialize => 0.05,
        }
    }
}

/// Progress notification: which stage, how far into it, and the overall
/// fraction complete.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Progress {
    pub stage: Stage,
    /// Units completed within the stage.
    pub done: usize,
    /// Total units in the stage.
    pub total: usize,
    /// Overall completion in `0.0..=1.0`, weighted across stages.
    pub fraction: f32,
}

/// Something went wrong. Carried to JS as a plain string; the pipeline's own
/// error types already render fully-formed messages.
#[derive(Debug, Clone)]
pub struct AnalyzeError(String);

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub type Result<T> = std::result::Result<T, AnalyzeError>;

/// How the host wants to be told about progress.
pub trait ProgressSink: Sync {
    fn report(&self, progress: Progress);
}

/// A sink that discards everything, for callers that do not need progress.
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn report(&self, _progress: Progress) {}
}

/// Holds the current stage and counts transitions, converting a `(done, total)`
/// pair inside one stage into an overall fraction.
///
/// The scan stage reports from inside rayon's worker pool, so the shared state
/// is atomic rather than `Cell`. On `wasm32-unknown-unknown` rayon falls back
/// to one thread, but the code must still satisfy the `Sync` bound that lets
/// the same pipeline run natively.
struct ProgressTracker<'a> {
    sink: &'a dyn ProgressSink,
    current: AtomicU8,
}

/// `Stage` encoded for the atomic, so the tracker stays `Sync`.
const STAGE_PARSE: u8 = 0;
const STAGE_CARVE: u8 = 1;
const STAGE_SCAN: u8 = 2;
const STAGE_INFER: u8 = 3;
const STAGE_SERIALIZE: u8 = 4;

const ALL_STAGES: [Stage; 5] = [
    Stage::Parse,
    Stage::Carve,
    Stage::Scan,
    Stage::Infer,
    Stage::Serialize,
];

impl<'a> ProgressTracker<'a> {
    fn new(sink: &'a dyn ProgressSink) -> Self {
        ProgressTracker {
            sink,
            current: AtomicU8::new(STAGE_PARSE),
        }
    }

    /// Announce a new stage, reporting it at 0%.
    fn enter(&self, stage: Stage) {
        self.current.store(stage as u8, Ordering::Relaxed);
        self.sink.report(self.at(stage, 0, 1));
    }

    /// Report `(done, total)` within the current stage.
    fn advance(&self, done: usize, total: usize) {
        let stage = self.current();
        self.sink.report(self.at(stage, done, total.max(1)));
    }

    fn current(&self) -> Stage {
        match self.current.load(Ordering::Relaxed) {
            STAGE_CARVE => Stage::Carve,
            STAGE_SCAN => Stage::Scan,
            STAGE_INFER => Stage::Infer,
            STAGE_SERIALIZE => Stage::Serialize,
            _ => Stage::Parse,
        }
    }

    fn at(&self, stage: Stage, done: usize, total: usize) -> Progress {
        let mut fraction = 0.0f32;
        for s in ALL_STAGES {
            if s.index() < stage.index() {
                fraction += s.weight();
            } else if s.index() == stage.index() {
                let within = (done as f32 / total as f32).clamp(0.0, 1.0);
                fraction += s.weight() * within;
                break;
            } else {
                break;
            }
        }
        Progress {
            stage,
            done,
            total,
            fraction: fraction.clamp(0.0, 1.0),
        }
    }
}

/// What a completed analysis produced, as owned Rust values.
///
/// This is the host-agnostic core of the crate: it holds no JS types, so it is
/// usable from Rust tests and from any other wasm host. The `wasm_bindgen`
/// layer below converts it to a JSON string for the browser.
pub struct Analysis {
    /// The object graph: nodes, edges, stats, arenas.
    pub graph: serde_json::Value,
    /// Metadata about the dump itself: format, process, thread count, and
    /// whether the dump looked truncated.
    pub meta: serde_json::Value,
    /// The core file's memory map, one entry per mapped range.
    pub maps: serde_json::Value,
}

/// Runs the full pipeline over an in-memory core dump.
///
/// `report` is called as the pipeline advances. It is invoked from inside
/// rayon's worker pool during the scan stage, so it must be cheap and must not
/// block: it should forward to a callback that is already cheap to call.
pub fn analyze_with(
    bytes: &[u8],
    options: &ScanOptions,
    report: &dyn ProgressSink,
) -> Result<Analysis> {
    if bytes.is_empty() {
        return Err(AnalyzeError("the file is empty".into()));
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(AnalyzeError(format!(
            "dump is {} MiB, over the {} MiB in-browser limit; use the \
             naksheap service for dumps this large",
            bytes.len() / (1024 * 1024),
            MAX_INPUT_BYTES / (1024 * 1024),
        )));
    }

    let tracker = ProgressTracker::new(report);

    // --- Parse ---
    tracker.enter(Stage::Parse);
    let parsed = naksheap_core_parse::elf::parse_elf_bytes(bytes)
        .map_err(|e| AnalyzeError(e.to_string()))?;
    tracker.advance(1, 1);

    // Build the image over the caller's bytes. `from_bytes` copies, and the
    // pipeline needs owned bytes because `Backing::Owned` is what the
    // filesystem-free path uses; the copy is the single largest transient
    // allocation in the whole run.
    let image = MappedImage::from_bytes(bytes.to_vec(), parsed.map.clone(), parsed.pointer_width);
    let truncated = image.is_truncated();

    // --- Carve ---
    tracker.enter(Stage::Carve);
    let inventory = carve(&image);
    tracker.advance(1, 1);

    // --- Scan ---
    tracker.enter(Stage::Scan);
    // rayon's pool may call this concurrently, so it must be Sync. The throttle
    // matters: crossing into JS is expensive, and a 100k-object dump would
    // otherwise emit 100k callbacks and make the UI slower than the analysis.
    let total_work = inventory.objects.len() + parsed.threads.len();
    // Forward at most ~200 updates across the whole scan, regardless of how
    // many objects the dump contains.
    let step = (total_work / 200).max(1);
    let scan = scan_with_progress(
        &image,
        &inventory,
        &parsed.threads,
        options,
        &|done, _total| {
            // This runs on rayon workers, possibly concurrently and out of
            // order, so it must not assume monotonicity. The modulo throttle
            // is best-effort: a busy UI still gets regular updates.
            if done % step == 0 || done == total_work {
                tracker.advance(done, total_work);
            }
        },
    );
    tracker.advance(total_work, total_work);

    // --- Infer ---
    tracker.enter(Stage::Infer);
    let graph = naksheap_inference::build_graph(&image, &inventory, &scan);
    tracker.advance(1, 1);

    // --- Serialize ---
    tracker.enter(Stage::Serialize);
    let graph_json = naksheap_inference::graph_to_json(&graph);

    let core = CoreFile {
        format: parsed.format,
        image,
        threads: parsed.threads.clone(),
        process_name: parsed.process_name.clone(),
        command_line: parsed.command_line.clone(),
        exec_path: parsed.exec_path.clone(),
        maps: parsed.map.clone(),
    };
    let meta = json!({
        "format": format_name(parsed.format),
        "process": core.process_name,
        "command_line": core.command_line,
        "exec_path": core.exec_path,
        "pointer_width": parsed.pointer_width,
        "threads": core.threads.len(),
        "truncated": truncated,
        "input_bytes": bytes.len(),
        "objects": inventory.objects.len(),
        "edges": scan.edges.len(),
        "roots": scan.roots.len(),
    });
    let maps =
        serde_json::to_value(parsed.map.iter().collect::<Vec<_>>()).unwrap_or_else(|_| json!([]));
    tracker.advance(1, 1);

    Ok(Analysis {
        graph: graph_json,
        meta,
        maps,
    })
}

/// Convenience wrapper for callers that do not need progress.
pub fn analyze(bytes: &[u8], options: &ScanOptions) -> Result<Analysis> {
    analyze_with(bytes, options, &NoProgress)
}

fn format_name(format: CoreFormat) -> &'static str {
    match format {
        CoreFormat::Elf64 => "elf64",
        CoreFormat::Elf32 => "elf32",
        CoreFormat::Minidump => "minidump",
    }
}

// ---------------------------------------------------------------------------
// JavaScript surface
// ---------------------------------------------------------------------------

/// Analyze a core dump fully in the browser and return the result as JSON.
///
/// `bytes` is the raw file. `on_progress` is called with a JSON-encoded
/// [`Progress`] object as work advances; pass `null`/undefined to skip it.
///
/// Returns a JSON string: `{ "graph": <object graph>, "meta": {...},
/// "maps": [...] }`. Throws a JS error with a human-readable message on a bad
/// input, since there is no meaningful "partial" result to return.
#[wasm_bindgen]
pub fn analyze_js(
    bytes: &[u8],
    on_progress: Option<js_sys::Function>,
) -> std::result::Result<String, JsValue> {
    let sink = JsProgress { on_progress };
    let analysis =
        analyze_with(bytes, &ScanOptions::default(), &sink).map_err(|e| JsValue::from_str(&e.0))?;

    let out = json!({
        "graph": analysis.graph,
        "meta": analysis.meta,
        "maps": analysis.maps,
    });
    serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Bridge from the Rust pipeline's progress trait to a JS callback.
struct JsProgress {
    on_progress: Option<js_sys::Function>,
}

impl ProgressSink for JsProgress {
    fn report(&self, progress: Progress) {
        let Some(cb) = &self.on_progress else { return };
        if let Ok(payload) = serde_json::to_string(&progress) {
            // A throw inside the page's callback must not abort the analysis.
            let _ = cb.call1(&JsValue::NULL, &JsValue::from_str(&payload));
        }
    }
}

/// The in-browser size cap, as a number of bytes, for the UI to compare against
/// before reading a large file.
#[wasm_bindgen]
pub fn max_input_bytes() -> usize {
    MAX_INPUT_BYTES
}
