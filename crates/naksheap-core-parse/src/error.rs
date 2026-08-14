use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file is not a recognized core dump or memory image (bad magic)")]
    UnsupportedFormat,

    #[error("ELF parse error: {0}")]
    Elf(#[from] object::Error),

    #[error("malformed core note: {0}")]
    BadNote(String),

    #[error("unsupported pointer width or architecture: {0}")]
    UnsupportedArch(String),

    #[error("address {0:#x} not mapped (or absent from dump)")]
    Unmapped(u64),

    #[error("truncated note descriptor: {0}")]
    Truncated(String),

    #[error("invalid argument: {0}")]
    Invalid(String),
}
