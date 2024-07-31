use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use anyhow::Result;

fn scan_for_unsafe_blocks(file_path: &str, unsafe_re: &Regex) -> Result<()> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut inside_unsafe_block = false;
    let mut line_number = 0;
    let mut unsafe_block_lines = vec![];

    for line in reader.lines() {
        line_number += 1;
        let line = line?;
        
        if unsafe_re.is_match(&line) {
            inside_unsafe_block = true;
            unsafe_block_lines.push((line_number, line.to_string())); // 使用 to_string() 克隆
        } else if inside_unsafe_block {
            unsafe_block_lines.push((line_number, line.to_string())); // 使用 to_string() 克隆
            if line.trim().ends_with('}') {
                if unsafe_block_lines.len() > 5 {
                    println!("File: {}", file_path);
                    println!("Starting line: {}", unsafe_block_lines[0].0);
                    println!("Content:");
                    for (_, ref line_content) in &unsafe_block_lines {
                        println!("{}", line_content);
                    }
                }
                inside_unsafe_block = false;
                unsafe_block_lines.clear();
            }
        }
    }
    
    Ok(())
}

fn process_directory(dir_path: &str, unsafe_re: &Regex) -> Result<()> {
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            process_directory(path.to_str().unwrap(), unsafe_re)?;
        } else if path.extension().map_or(false, |ext| ext == "rs") {
            println!("Processing file: {}", path.display());
            scan_for_unsafe_blocks(path.to_str().unwrap(), unsafe_re)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let crate_dir = r"C:\Users\ROG\Desktop\overunsafe库\rust-stackvector-d0382d5ef903fc96bdcc08c02e36e6dd2eda11a5"; // Adjust to the directory of your crate

    let unsafe_re = Regex::new(r"^\s*unsafe\s*\{")?;
    
    process_directory(crate_dir, &unsafe_re)?;

    Ok(())
}
