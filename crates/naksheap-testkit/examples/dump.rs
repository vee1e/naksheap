//! Debug helper: dump raw memory (words / strings) from a core file.
//! Usage: cargo run -p naksheap-testkit --example dump -- <core> <addr1> <addr2> ...
//! Each <addr> may be hex (0x...) and is printed as a 8-byte word.

use naksheap_core_parse::AddressSpace;
use naksheap_core_parse::open;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: dump <core> <addr>...");
        std::process::exit(2);
    }
    let core = open(std::path::Path::new(&args[1])).expect("open core");
    for a in &args[2..] {
        let addr = u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("addr");
        print!("{addr:#018x}: ");
        for off in 0..8 {
            let w = core.image.read_word(addr + off * 8);
            match w {
                Some(w) => print!("[{off:#x}]={w:#018x} "),
                None => print!("[?] "),
            }
        }
        println!();
    }
}
