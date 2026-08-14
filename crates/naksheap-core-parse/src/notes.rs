use crate::error::{Error, Result};

/// A tiny endian-aware cursor used for decoding core note descriptors.
/// Handles both little- and big-endian at runtime via an `le` flag.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub le: bool,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], le: bool) -> Self {
        Reader { data, pos: 0, le }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated(format!(
                "need {n} bytes, have {}",
                self.remaining()
            )));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(if self.le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(if self.le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(if self.le {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    }

    /// Reads a native-width unsigned integer (4 or 8 bytes).
    pub fn word(&mut self, width: u8) -> Result<u64> {
        match width {
            4 => self.u32().map(u64::from),
            8 => self.u64(),
            w => Err(Error::UnsupportedArch(format!("word width {w}"))),
        }
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Reads a NUL-terminated ASCII string.
    pub fn cstr(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let end = self.pos;
        // consume the NUL if present
        if self.pos < self.data.len() {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.data[start..end]).map_err(|_| {
            Error::BadNote("non-UTF8 string in note descriptor".to_string())
        })?;
        Ok(s.to_string())
    }

    /// Reads a fixed-length string, trimming trailing NULs and whitespace.
    pub fn fixed_string(&mut self, n: usize) -> Result<String> {
        let b = self.take(n)?;
        let end = b
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(b.len());
        Ok(String::from_utf8_lossy(&b[..end]).trim().to_string())
    }
}

/// An ELF core note.
#[derive(Debug, Clone)]
pub struct Note<'a> {
    pub n_type: u32,
    pub name: &'a [u8],
    pub desc: &'a [u8],
}

/// Parses the notes inside a `PT_NOTE` segment.
pub fn parse_notes(segment: &[u8], le: bool) -> Result<Vec<Note<'_>>> {
    let mut notes = Vec::new();
    let mut pos = 0usize;
    while pos + 12 <= segment.len() {
        let mut r = Reader::new(&segment[pos..], le);
        let namesz = r.u32()? as usize;
        let descsz = r.u32()? as usize;
        let n_type = r.u32()?;
        let name_start = pos + 12;
        let desc_start = name_start + align4(namesz);
        let next = desc_start + align4(descsz);
        if next > segment.len() {
            return Err(Error::BadNote(format!(
                "note at offset {pos} exceeds segment ({} > {})",
                next,
                segment.len()
            )));
        }
        notes.push(Note {
            n_type,
            name: &segment[name_start..name_start + namesz],
            desc: &segment[desc_start..desc_start + descsz],
        });
        pos = next;
    }
    Ok(notes)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_AUXV: u32 = 6;
pub const NT_FILE: u32 = 0x46494c45; // "FILE"
pub const NT_SIGINFO: u32 = 0x53494749; // "SIGI"

/// One entry from NT_FILE.
#[derive(Debug, Clone)]
pub struct NtFileEntry {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub path: String,
}

/// Decodes an NT_FILE descriptor into file-backed mapping entries.
pub fn parse_nt_file(desc: &[u8], le: bool, ptr_bytes: u8) -> Result<Vec<NtFileEntry>> {
    let mut r = Reader::new(desc, le);
    let count = r.word(ptr_bytes)?;
    let _page_size = r.word(ptr_bytes)?;
    if count > 1 << 20 {
        return Err(Error::BadNote(format!(
            "implausible NT_FILE count {count}"
        )));
    }
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let start = r.word(ptr_bytes)?;
        let end = r.word(ptr_bytes)?;
        let file_offset = r.word(ptr_bytes)?;
        entries.push(NtFileEntry {
            start,
            end,
            file_offset,
            path: String::new(),
        });
    }
    // Filename area: `count` NUL-terminated strings, in entry order.
    let mut paths = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match r.cstr() {
            Ok(s) => paths.push(s),
            Err(_) => paths.push(String::new()),
        }
    }
    for (e, p) in entries.iter_mut().zip(paths) {
        e.path = p;
    }
    Ok(entries)
}

/// Parsed NT_PRSTATUS register block.
#[derive(Debug, Clone)]
pub struct PrStatus {
    pub tid: i32,
    /// Native-width register words in architecture order (x86_64: user_regs_struct).
    pub regs: Vec<u64>,
    pub ip: u64,
    pub sp: u64,
}

/// Offsets within `struct elf_prstatus` (verified against Linux
/// `include/linux/elfcore.h`). Note that `struct elf_siginfo` is 12 bytes
/// (3 ints), NOT the 16 bytes of userspace `siginfo_t`, which is why `pr_reg`
/// sits at 0x70 (64-bit) and not 0x78.
const PR_REG_OFFSET_64: usize = 0x70;
const PR_REG_OFFSET_32: usize = 0x48;
/// Offset of `pr_pid` within `struct elf_prstatus`.
const PR_PID_OFFSET_64: usize = 0x20;
const PR_PID_OFFSET_32: usize = 0x18;
/// Offset of `pr_cursig` (short) within `struct elf_prstatus`.
pub const PR_CURSIG_OFFSET: usize = 0x0c;

/// Decodes an NT_PRSTATUS descriptor for the given architecture.
///
/// `reg_count`/`ip_idx`/`sp_idx` identify the register array layout:
/// - x86_64: 27 regs (user_regs_struct), ip = 16 (rip), sp = 19 (rsp)
/// - x86: 17 regs, ip = 12 (eip), sp = 15 (esp)
/// - aarch64: 34 regs, ip = 32 (pc), sp = 31 (sp)
pub fn parse_prstatus(desc: &[u8], le: bool, ptr_bytes: u8, reg_count: usize, ip_idx: usize, sp_idx: usize) -> Result<PrStatus> {
    let off = if ptr_bytes == 8 {
        PR_REG_OFFSET_64
    } else {
        PR_REG_OFFSET_32
    };
    let reg_bytes = reg_count * ptr_bytes as usize;
    if desc.len() < off + reg_bytes {
        return Err(Error::BadNote(format!(
            "PRSTATUS too short: {} < {}",
            desc.len(),
            off + reg_bytes
        )));
    }
    let mut r = Reader::new(&desc[off..], le);
    let mut regs = Vec::with_capacity(reg_count);
    for _ in 0..reg_count {
        regs.push(r.word(ptr_bytes)?);
    }
    let tid_off = if ptr_bytes == 8 { PR_PID_OFFSET_64 } else { PR_PID_OFFSET_32 };
    let tid = {
        let mut tr = Reader::new(&desc[tid_off..], le);
        tr.word(ptr_bytes).unwrap_or(0) as i32
    };
    let ip = regs.get(ip_idx).copied().unwrap_or(0);
    let sp = regs.get(sp_idx).copied().unwrap_or(0);
    Ok(PrStatus { tid, regs, ip, sp })
}

/// Offsets within `struct elf_prpsinfo` (verified against Linux
/// `include/linux/elfcore.h`): 4 char fields + `pr_flag` (word-aligned) +
/// uid/gid + 4 pids lands `pr_fname` at 0x28 (64-bit) / 0x20 (32-bit).
const PRPSINFO_FNAME_OFFSET_64: usize = 0x28;
const PRPSINFO_FNAME_OFFSET_32: usize = 0x20;

/// Decodes NT_PRPSINFO: process name + command line.
pub fn parse_prpsinfo(desc: &[u8], le: bool, ptr_bytes: u8) -> (Option<String>, Option<String>) {
    let off_fname = if ptr_bytes == 8 {
        PRPSINFO_FNAME_OFFSET_64
    } else {
        PRPSINFO_FNAME_OFFSET_32
    };
    if desc.len() < off_fname + 16 + 80 {
        return (None, None);
    }
    let mut r = Reader::new(&desc[off_fname..], le);
    let name = r.fixed_string(16).ok();
    let cmdline = r.fixed_string(80).ok();
    (name, cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kernel-accurate x86_64 NT_PRSTATUS descriptor built by hand so the
    /// parser is validated against the REAL `struct elf_prstatus` layout
    /// (`pr_reg` at 0x70, `pr_pid` at 0x20, desc size 0x150), independent of
    /// the testkit fixture generator.
    fn kernel_accurate_prstatus() -> Vec<u8> {
        let mut desc = vec![0u8; 0x150];
        // pr_pid @ 0x20 (u32 LE)
        desc[0x20..0x24].copy_from_slice(&4242u32.to_le_bytes());
        // pr_cursig (short) @ 0x0c
        desc[0x0c..0x0e].copy_from_slice(&11u16.to_le_bytes());
        // 27 x86_64 user_regs_struct words @ 0x70; rbp(4), rip(16), rsp(19)
        let mut put = |idx: usize, v: u64| {
            let off = 0x70 + idx * 8;
            desc[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        put(4, 0x7fff_0000_1f00); // rbp
        put(16, 0x401234);        // rip
        put(19, 0x7fff_0000_2000); // rsp
        put(14, 0x7f00_0000_0040); // rdi -> a heap pointer
        desc
    }

    #[test]
    fn prstatus_kernel_layout_64() {
        let desc = kernel_accurate_prstatus();
        let ps = parse_prstatus(&desc, true, 8, 27, 16, 19).expect("parse");
        assert_eq!(ps.tid, 4242);
        assert_eq!(ps.ip, 0x401234);
        assert_eq!(ps.sp, 0x7fff_0000_2000);
        assert_eq!(ps.regs[4], 0x7fff_0000_1f00);
        assert_eq!(ps.regs[14], 0x7f00_0000_0040);
    }

    #[test]
    fn prpsinfo_kernel_layout_64() {
        let mut desc = vec![0u8; 0x88];
        // pr_state @ 0, pr_sname @ 1, pr_zomb @ 2, pr_nice @ 3
        desc[1] = b'R';
        let fname = b"toy-server\0";
        desc[0x28..0x28 + fname.len()].copy_from_slice(fname);
        let args = b"./toy-server --listen :8080\0";
        desc[0x38..0x38 + args.len()].copy_from_slice(args);
        let (name, cmdline) = parse_prpsinfo(&desc, true, 8);
        assert_eq!(name.as_deref(), Some("toy-server"));
        assert_eq!(cmdline.as_deref(), Some("./toy-server --listen :8080"));
    }

    #[test]
    fn prstatus_truncated_rejected() {
        let desc = vec![0u8; 0x70]; // too short for regs at 0x70
        assert!(parse_prstatus(&desc, true, 8, 27, 16, 19).is_err());
    }
}
