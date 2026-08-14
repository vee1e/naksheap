//! Layout-based clustering of carved heap objects.
//!
//! Objects are grouped by size, then by the shape of their words at aligned
//! (8-byte) offsets. A column is classified as *pointer* when at least half of
//! the members in a size group hold a pointer there (and the column is not
//! all-zero), and as *string* when at least half hold printable ASCII there.
//! A zero word at a pointer/string column is a nullable field slot and never
//! splits a member off. Objects whose per-member shape agrees with the group's
//! majority shape form the group's main cluster; deviant members are split into
//! their own clusters keyed by their identical shapes.

use std::collections::{BTreeMap, HashMap, HashSet};

use naksheap_allocator_heuristics::{Object, ObjectState};
use naksheap_core_parse::AddressSpace;
use naksheap_pointer_scan::Edge;

/// Fraction of members that must hold a pointer for a column to be a pointer
/// field. 50% (a majority) keeps nullable pointer fields from fragmenting.
const POINTER_THRESHOLD: f64 = 0.5;
/// Fraction of members that must hold a string for a column to be a string
/// field.
const STRING_THRESHOLD: f64 = 0.5;
/// Minimum run length of printable bytes for a word to read as a string.
const STRING_RUN: u32 = 4;
/// A string needs at least two distinct byte values, so constant fill patterns
/// ('AAAAAAAA') are padding, not text.
const STRING_MIN_DISTINCT: u32 = 2;

/// A group of objects sharing the same size and word shape.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LayoutCluster {
    pub size: u64,
    /// Object addresses of the members.
    pub members: Vec<u64>,
    /// True at each aligned offset classified as a pointer column.
    pub pointer_mask: Vec<bool>,
    /// True at each aligned offset classified as a string column.
    pub string_mask: Vec<bool>,
}

/// Address-space targets used for pointer classification: carved object
/// ranges plus known pointer-edge targets.
struct TargetIndex {
    ranges: Vec<(u64, u64)>,
    edge_targets: HashSet<u64>,
}

impl TargetIndex {
    fn contains(&self, v: u64) -> bool {
        if self.edge_targets.contains(&v) {
            return true;
        }
        // `ranges` is sorted by start address; a stabbing lookup replaces the
        // former linear scan (which made clustering quadratic on dumps where
        // many object words do not resolve to mapped memory).
        let idx = self.ranges.partition_point(|&(a, _)| a <= v);
        if idx == 0 {
            return false;
        }
        let (a, size) = self.ranges[idx - 1];
        v < a.saturating_add(size)
    }
}

/// Groups eligible (Allocated/Mmap) objects by layout similarity.
///
/// Freed objects are skipped for typing purposes; they are never clustered.
pub fn cluster_objects(
    image: &(dyn AddressSpace + Sync),
    objects: &[Object],
    edges: &[Edge],
) -> Vec<LayoutCluster> {
    let eligible: Vec<&Object> = objects
        .iter()
        .filter(|o| matches!(o.state, ObjectState::Allocated | ObjectState::Mmap))
        .collect();

    let mut ranges: Vec<(u64, u64)> = eligible.iter().map(|o| (o.addr, o.size)).collect();
    ranges.sort_by_key(|&(a, _)| a);
    let targets = TargetIndex {
        ranges,
        edge_targets: edges.iter().map(|e| e.to).collect(),
    };

    let mut by_size: BTreeMap<u64, Vec<&Object>> = BTreeMap::new();
    for o in eligible {
        by_size.entry(o.size).or_default().push(o);
    }

    let mut clusters: Vec<LayoutCluster> = Vec::new();
    for (size, members) in by_size {
        let agg = majority_masks(image, size, &members, &targets);

        type MemberMask = (Vec<bool>, Vec<bool>);
        let mut main: Vec<u64> = Vec::new();
        let mut deviants: Vec<(&Object, MemberMask)> = Vec::new();
        for m in members {
            let indiv = individual_masks(image, m, &targets);
            if agrees_with_aggregate(image, m, &indiv, &agg) {
                main.push(m.addr);
            } else {
                deviants.push((m, indiv));
            }
        }

        if !main.is_empty() {
            clusters.push(LayoutCluster {
                size,
                members: main,
                pointer_mask: agg.0,
                string_mask: agg.1,
            });
        }

        // Members that deviate from the majority shape are grouped among
        // themselves by their identical shapes.
        let mut dev_by_mask: HashMap<MemberMask, Vec<u64>> = HashMap::new();
        for (m, mask) in deviants {
            dev_by_mask.entry(mask).or_default().push(m.addr);
        }
        let addr_to_obj: HashMap<u64, &Object> = objects
            .iter()
            .map(|o| (o.addr, o))
            .collect();
        for (_, addrs) in dev_by_mask {
            let sub_members: Vec<&Object> = addrs
                .iter()
                .filter_map(|a| addr_to_obj.get(a).copied())
                .collect();
            let (pm, sm) = majority_masks(image, size, &sub_members, &targets);
            clusters.push(LayoutCluster {
                size,
                members: addrs,
                pointer_mask: pm,
                string_mask: sm,
            });
        }
    }

    clusters.sort_by_key(|c| std::cmp::Reverse(c.members.len()));
    clusters
}

/// Majority-vote shape masks over a group of same-size objects.
fn majority_masks(
    image: &(dyn AddressSpace + Sync),
    size: u64,
    members: &[&Object],
    targets: &TargetIndex,
) -> (Vec<bool>, Vec<bool>) {
    let n = members.len().max(1);
    let n_words = size.div_ceil(8) as usize;
    let mut ptr_cnt = vec![0usize; n_words];
    let mut str_cnt = vec![0usize; n_words];
    let mut zero_cnt = vec![0usize; n_words];

    for m in members {
        let (pm, sm) = individual_masks(image, m, targets);
        for i in 0..n_words {
            if pm[i] {
                ptr_cnt[i] += 1;
            }
            if sm[i] {
                str_cnt[i] += 1;
            }
        }
        for (i, z) in zero_cnt.iter_mut().enumerate() {
            let off = i as u64 * 8;
            if off < m.size && image.read_word(m.addr.saturating_add(off)) == Some(0) {
                *z += 1;
            }
        }
    }

    let ratio = |c: usize| c as f64 / n as f64;
    // A column is padding only when *every* member is zero there; a mixed
    // column (some NULL, some pointer) is a nullable pointer field.
    let pointer_mask = (0..n_words)
        .map(|i| ratio(ptr_cnt[i]) >= POINTER_THRESHOLD && zero_cnt[i] < n)
        .collect();
    let string_mask = (0..n_words)
        .map(|i| ratio(str_cnt[i]) >= STRING_THRESHOLD)
        .collect();
    (pointer_mask, string_mask)
}

/// Per-member shape mask: each aligned word classified pointer/string.
fn individual_masks(
    image: &(dyn AddressSpace + Sync),
    obj: &Object,
    targets: &TargetIndex,
) -> (Vec<bool>, Vec<bool>) {
    let n_words = obj.size.div_ceil(8) as usize;
    let mut ptr = vec![false; n_words];
    let mut s = vec![false; n_words];
    for i in 0..n_words {
        let off = i as u64 * 8;
        let addr = obj.addr.saturating_add(off);
        if let Some(v) = image.read_word(addr) {
            ptr[i] = is_pointer_value(image, v, targets);
            s[i] = is_string_value(image, obj.addr, off);
        }
    }
    (ptr, s)
}

/// A member belongs to the group when every column is compatible with the
/// aggregate shape. A zero word at an aggregate pointer/string column is a
/// nullable field slot, so it stays with the group instead of splitting.
fn agrees_with_aggregate(
    image: &(dyn AddressSpace + Sync),
    m: &Object,
    indiv: &(Vec<bool>, Vec<bool>),
    agg: &(Vec<bool>, Vec<bool>),
) -> bool {
    let n_words = indiv
        .0
        .len()
        .max(indiv.1.len())
        .max(agg.0.len())
        .max(agg.1.len());
    for i in 0..n_words {
        let off = i as u64 * 8;
        if off >= m.size {
            break;
        }
        let word = image.read_word(m.addr.saturating_add(off)).unwrap_or(0);
        let is_ptr = indiv.0.get(i).copied().unwrap_or(false);
        let is_str = indiv.1.get(i).copied().unwrap_or(false);
        let agg_ptr = agg.0.get(i).copied().unwrap_or(false);
        let agg_str = agg.1.get(i).copied().unwrap_or(false);

        if agg_ptr {
            // Nullable pointer column: zero is a compatible NULL slot; any
            // other non-pointer value deviates.
            if !is_ptr && word != 0 {
                return false;
            }
        } else if is_ptr {
            return false;
        }

        if agg_str {
            // Nullable string column: a zero or a pointer is compatible.
            if !is_str && word != 0 && !is_ptr {
                return false;
            }
        } else if is_str {
            return false;
        }
    }
    true
}

/// A word is a pointer when it lands in a mapped/readable range, inside another
/// carved object, or in a file-backed (rodata/vtable) range. Zero is never a
/// pointer.
fn is_pointer_value(image: &(dyn AddressSpace + Sync), v: u64, targets: &TargetIndex) -> bool {
    if v == 0 {
        return false;
    }
    if image.read_bytes(v, 8).is_some() {
        return true;
    }
    if targets.contains(v) {
        return true;
    }
    image.is_file_backed(v)
}

/// A word is a string when the object's own 8 bytes at the offset are a
/// printable run with enough variance, or when the word's value points to
/// at least [`STRING_RUN`] consecutive printable bytes with at least
/// [`STRING_MIN_DISTINCT`] distinct values. Constant runs like `"AAAAAAAA"`
/// are fill/padding, not strings.
fn is_string_value(image: &(dyn AddressSpace + Sync), obj_addr: u64, off: u64) -> bool {
    let addr = obj_addr.saturating_add(off);
    // Inline case: a lone UTF-8 continuation byte (0x80..=0xbf) is not text on
    // its own, so exclude it from the printable set here.
    if let Some(bytes) = image.read_bytes(addr, 8) {
        if printable_run_ok(bytes, true) {
            return true;
        }
    }
    if let Some(v) = image.read_word(addr) {
        if v != 0 {
            if let Some(bytes) = image.read_bytes(v, 16) {
                if printable_run_ok(bytes, false) {
                    return true;
                }
            }
        }
    }
    false
}

/// True when `bytes` contains a run of at least [`STRING_RUN`] printable bytes
/// with at least [`STRING_MIN_DISTINCT`] distinct printable values. When
/// `ascii_only` the UTF-8 continuation range is excluded (for inline text).
fn printable_run_ok(bytes: &[u8], ascii_only: bool) -> bool {
    let mut run = 0u32;
    let mut seen = [false; 256];
    let mut distinct = 0u32;
    for &b in bytes {
        let printable = if ascii_only {
            is_ascii_text(b)
        } else {
            is_printable(b)
        };
        if printable {
            run += 1;
            if !seen[b as usize] {
                seen[b as usize] = true;
                distinct += 1;
            }
            if run >= STRING_RUN && distinct >= STRING_MIN_DISTINCT {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Printable ASCII plus control whitespace; excludes UTF-8 continuation bytes.
fn is_ascii_text(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || matches!(b, 0x09 | 0x0a | 0x0d)
}

/// Printable ASCII, control-whitespace, and UTF-8 continuation bytes.
pub(crate) fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
        || matches!(b, 0x09 | 0x0a | 0x0d)
        || (0x80..=0xbf).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use naksheap_core_parse::{MappedImage, MemoryMap, MemoryRange, Perms, RangeKind};

    const HEAP: u64 = 0x600000;

    fn obj(addr: u64, size: u64) -> Object {
        Object {
            addr,
            size,
            state: ObjectState::Allocated,
            arena: None,
            chunk_header: addr.saturating_sub(0x10),
            freed_reason: None,
        }
    }

    struct Img {
        bytes: Vec<u8>,
        ranges: Vec<MemoryRange>,
    }

    impl Img {
        fn new() -> Self {
            Img {
                bytes: vec![0x41u8; 0x10000],
                ranges: vec![MemoryRange {
                    start: HEAP,
                    end: HEAP + 0x10000,
                    file_offset: 0,
                    file_size: 0x10000,
                    perms: Perms {
                        read: true,
                        write: true,
                        execute: false,
                    },
                    kind: RangeKind::Anon,
                    path: None,
                    name: Some("[heap]".into()),
                }],
            }
        }

        fn put(&mut self, addr: u64, v: u64) {
            let off = (addr - HEAP) as usize;
            self.bytes[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }

        fn image(self) -> MappedImage {
            MappedImage::from_bytes(self.bytes, MemoryMap::from_ranges(self.ranges), 8)
        }
    }

    #[test]
    fn cluster_same_size_identical_pointer_masks_group_together() {
        let mut img = Img::new();
        let a = obj(HEAP + 0x20, 0x20);
        let b = obj(HEAP + 0x50, 0x20);
        let c = obj(HEAP + 0x80, 0x20);
        img.put(a.addr, b.addr);
        img.put(b.addr, c.addr);
        img.put(c.addr, a.addr);
        let image = img.image();
        let objects = vec![a, b, c];

        let clusters = cluster_objects(&image, &objects, &[]);
        assert_eq!(clusters.len(), 1);
        let cl = &clusters[0];
        assert_eq!(cl.size, 0x20);
        assert_eq!(cl.members.len(), 3);
        assert!(cl.pointer_mask[0]);
        assert!(!cl.pointer_mask[1]);
    }

    #[test]
    fn cluster_different_sizes_are_not_merged() {
        let mut img = Img::new();
        let a = obj(HEAP + 0x20, 0x20);
        let b = obj(HEAP + 0x50, 0x20);
        let c = obj(HEAP + 0x80, 0x20);
        let d = obj(HEAP + 0xc0, 0x30);
        img.put(a.addr, b.addr);
        img.put(b.addr, c.addr);
        img.put(c.addr, a.addr);
        img.put(d.addr, HEAP + 0x1000);
        let image = img.image();
        let objects = vec![a, b, c, d];

        let clusters = cluster_objects(&image, &objects, &[]);
        let sizes: Vec<u64> = clusters.iter().map(|cl| cl.size).collect();
        assert_eq!(clusters.len(), 2, "expected one cluster per size, got {sizes:?}");
        assert!(sizes.contains(&0x20));
        assert!(sizes.contains(&0x30));
    }

    #[test]
    fn cluster_nullable_pointer_column_stays_together() {
        // Four 0x20 objects; two hold a real pointer at word0 and two hold
        // NULL (zero). The column is a pointer in 50% of members, so it is a
        // pointer column, and the NULL slots are nullable field values that do
        // not split the cluster.
        let mut img = Img::new();
        let a = obj(HEAP + 0x20, 0x20);
        let b = obj(HEAP + 0x50, 0x20);
        let c = obj(HEAP + 0x80, 0x20);
        let d = obj(HEAP + 0xb0, 0x20);
        img.put(a.addr, HEAP + 0x1000);
        img.put(b.addr, HEAP + 0x1008);
        img.put(c.addr, 0);
        img.put(d.addr, 0);
        let image = img.image();
        let objects = vec![a, b, c, d];

        let clusters = cluster_objects(&image, &objects, &[]);
        assert_eq!(clusters.len(), 1, "nullable pointer column must not split");
        let cl = &clusters[0];
        assert_eq!(cl.members.len(), 4);
        assert!(
            cl.pointer_mask.first() == Some(&true),
            "50% pointer column must remain a pointer field"
        );
    }

    #[test]
    fn cluster_all_zero_column_is_padding_not_pointer() {
        // A column that is zero in every member is padding and never a pointer
        // field, even though 0.5 <= zero ratio would have flagged it before.
        let mut img = Img::new();
        let a = obj(HEAP + 0x20, 0x20);
        let b = obj(HEAP + 0x50, 0x20);
        let c = obj(HEAP + 0x80, 0x20);
        img.put(a.addr, HEAP + 0x1000);
        img.put(b.addr, HEAP + 0x1008);
        img.put(c.addr, HEAP + 0x1010);
        // Word1 is zero in every member (fill is 0x41, so zero it out).
        img.put(a.addr + 8, 0);
        img.put(b.addr + 8, 0);
        img.put(c.addr + 8, 0);
        let image = img.image();
        let objects = vec![a, b, c];

        let clusters = cluster_objects(&image, &objects, &[]);
        assert_eq!(clusters.len(), 1);
        let cl = &clusters[0];
        assert_eq!(cl.members.len(), 3);
        assert!(cl.pointer_mask[0], "pointer column at word0");
        assert!(
            !cl.pointer_mask[1],
            "all-zero column must be treated as padding"
        );
    }

    #[test]
    fn cluster_skips_freed_objects() {
        let mut img = Img::new();
        let a = obj(HEAP + 0x20, 0x20);
        let mut freed = obj(HEAP + 0x50, 0x20);
        freed.state = ObjectState::Freed;
        img.put(a.addr, freed.addr);
        let image = img.image();
        let objects = vec![a.clone(), freed.clone()];

        let clusters = cluster_objects(&image, &objects, &[]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].members, vec![a.addr]);
        assert!(!clusters[0].members.contains(&freed.addr));
    }
}
