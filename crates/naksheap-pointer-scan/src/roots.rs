use naksheap_core_parse::{AddressSpace, ThreadContext};

use crate::{Edge, EdgeSource, ObjectIndex, Root, RootSource, ScanOptions};

/// Upper bound on stack bytes scanned per thread, to bound cost on huge stacks.
const MAX_STACK_SCAN_BYTES: u64 = 4 * 1024 * 1024;

/// Upper bound on the number of [`RootSource::Stack`] roots collected per
/// thread, to bound work on corrupted or pathological stacks.
const MAX_STACK_ROOTS: usize = 4096;

/// Collects root pointer candidates from thread registers and stacks.
///
/// Registers: each non-zero register word that lands inside a carved object
/// becomes a [`Root`] with source [`RootSource::Register`] and `addr` 0.
///
/// Stacks: the LIVE frame region of the mapped range containing each thread's
/// `sp` is read word-by-word, starting at `sp` and scanning UP to the highest
/// mapped address (bounded to the first 4 MiB above `sp` and only for writable
/// ranges). Dead frames below `sp` are already unwound and are never scanned.
/// Every word that points into a carved object becomes a [`Root`] with source
/// [`RootSource::Stack`] and `addr` equal to the stack address. Words equal to
/// `sp` itself or to the stack base are skipped as noise, and the number of
/// stack roots per thread is capped at [`MAX_STACK_ROOTS`].
pub fn collect_roots(
    image: &(dyn AddressSpace + Sync),
    threads: &[ThreadContext],
    index: &ObjectIndex,
) -> Vec<Root> {
    let defaults = ScanOptions::default();
    let mut roots = Vec::new();
    for thread in threads {
        let (r, _) = scan_thread(image, thread, index, &defaults);
        roots.extend(r);
    }
    roots
}

/// Scans one thread for root candidates, returning both the roots and the
/// matching root edges. Shared by [`collect_roots`] (which keeps only the
/// roots) and the full [`crate::scan`] (which needs the edges too).
pub(crate) fn scan_thread(
    image: &(dyn AddressSpace + Sync),
    thread: &ThreadContext,
    index: &ObjectIndex,
    options: &ScanOptions,
) -> (Vec<Root>, Vec<Edge>) {
    let mut roots = Vec::new();
    let mut edges = Vec::new();

    if options.scan_registers {
        for w in &thread.reg_words {
            if *w == 0 {
                continue;
            }
            if let Some(t) = index.target_at(*w) {
                roots.push(Root {
                    value: *w,
                    source: RootSource::Register,
                    addr: 0,
                });
                edges.push(Edge {
                    from: 0,
                    to: t.addr,
                    offset: 0,
                    confirmed: false,
                    source: EdgeSource::Register,
                });
            }
        }
    }

    if options.scan_stacks {
        if let Some(range) = image.range_at(thread.sp) {
            if range.is_writable() && range.perms.read {
                let word = image.pointer_width() as u64;
                // Scan only the LIVE frame region: start at `sp` and go up
                // toward the highest address in the mapping. Bytes below `sp`
                // are dead, already-unwound frames and are skipped. The end is
                // still bounded by MAX_STACK_SCAN_BYTES above `sp`.
                let end = thread
                    .sp
                    .saturating_add(MAX_STACK_SCAN_BYTES)
                    .min(range.end);
                let mut addr = thread.sp;
                let mut stack_roots = 0usize;
                while let Some(next) = addr.checked_add(word) {
                    if next > end {
                        break;
                    }
                    if let Some(w) = image.read_word(addr) {
                        // Skip noise words equal to `sp` itself or the stack
                        // base: they describe stack frames, not heap roots.
                        if w != 0 && w != thread.sp && w != range.start {
                            if let Some(t) = index.target_at(w) {
                                roots.push(Root {
                                    value: w,
                                    source: RootSource::Stack,
                                    addr,
                                });
                                edges.push(Edge {
                                    from: 0,
                                    to: t.addr,
                                    offset: addr,
                                    confirmed: false,
                                    source: EdgeSource::Stack,
                                });
                                stack_roots += 1;
                                if stack_roots >= MAX_STACK_ROOTS {
                                    break;
                                }
                            }
                        }
                    }
                    addr = next;
                }
            }
        }
    }

    (roots, edges)
}
