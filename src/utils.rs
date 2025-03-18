use std::fs::File;
use std::io::{self, Write};

pub fn save_to_file(base_filename: &str, content: &str) -> io::Result<()> {
    let filename = format!("{}.txt", base_filename);
    let mut file = File::create(&filename)?;
    file.write_all(content.as_bytes())?;
    println!("📂 Results saved to {}", filename);
    Ok(())
}