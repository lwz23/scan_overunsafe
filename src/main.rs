use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use anyhow::Result;
use syn::{ItemFn, ImplItem, visit::{self, Visit}, parse_file, Attribute, Expr, Block, Stmt};
use quote::quote;
use walkdir::WalkDir;
use regex::Regex;

/// Struct to visit functions and methods in the Rust code.
struct FunctionVisitor<'a> {
    file_path: &'a str, // 添加文件路径字段
    outputted_functions: &'a Arc<Mutex<HashSet<String>>>,
}

impl<'a, 'ast> Visit<'ast> for FunctionVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let function_name = node.sig.ident.to_string();

        if !self.is_test_function(&node.attrs)
            && !self.outputted_functions.lock().unwrap().contains(&function_name)
        {
            let start_line = node.sig.ident.span().start().line;
            let end_line = node.block.brace_token.span.close().end().line;
            let has_safety_comment = scan_safety_comments(self.file_path, start_line, end_line);

            let mut checker = UnsafeBlockChecker {
                has_large_unsafe: false,
                has_unsafe: false,
                current_function_name: function_name.clone(),
                current_file_path: self.file_path.to_string(),
                has_safety_comment,
            };

            checker.visit_block(&node.block);

            if checker.has_large_unsafe || (checker.has_unsafe && !has_safety_comment) {
                let function_code = quote! {
                    #node
                };
                let formatted_code = prettyplease::unparse(&syn::parse_quote!(#function_code));
                let output = format!(
                    "Found function with unsafe block in {}:\nFile: {}\nStart Line: {}, End Line: {:?}\n{}\n\n",
                    function_name, self.file_path, start_line, end_line, formatted_code
                );

                // Output to file with lock
                {
                    let mut log_file = LOG_FILE.lock().unwrap();
                    writeln!(log_file, "{}", output).expect("Failed to write to log file");
                }
            }

            // Add function to the set
            self.outputted_functions.lock().unwrap().insert(function_name);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        for item in &node.items {
            if let ImplItem::Fn(method) = item {
                let method_name = method.sig.ident.to_string();

                if !self.is_test_function(&method.attrs)
                    && !self.outputted_functions.lock().unwrap().contains(&method_name)
                {
                    let start_line = method.sig.ident.span().start().line;
                    let end_line = method.block.brace_token.span.close().end().line;
                    let has_safety_comment = scan_safety_comments(self.file_path, start_line, end_line);

                    let mut checker = UnsafeBlockChecker {
                        has_large_unsafe: false,
                        has_unsafe: false,
                        current_function_name: method_name.clone(),
                        current_file_path: self.file_path.to_string(),
                        has_safety_comment,
                    };

                    checker.visit_block(&method.block);

                    if checker.has_large_unsafe || (checker.has_unsafe && !has_safety_comment) {
                        let method_code = quote! {
                            #method
                        };
                        let formatted_code = prettyplease::unparse(&syn::parse_quote!(#method_code));
                        let output = format!(
                            "Found method with unsafe block in {}:\nFile: {}\nStart Line: {}, End Line: {:?}\n{}\n\n",
                            method_name, self.file_path, start_line, end_line, formatted_code
                        );

                        // Output to file with lock
                        {
                            let mut log_file = LOG_FILE.lock().unwrap();
                            writeln!(log_file, "{}", output).expect("Failed to write to log file");
                        }
                    }

                    // Add method to the set
                    self.outputted_functions.lock().unwrap().insert(method_name);
                }
            }
        }
        // Visit child nodes
        visit::visit_item_impl(self, node);
    }
}

impl<'a> FunctionVisitor<'a> {
    fn is_test_function(&self, attrs: &[Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("test"))
    }
}

/// UnsafeBlockChecker is responsible for detecting unsafe blocks within code.
struct UnsafeBlockChecker {
    has_large_unsafe: bool,
    has_unsafe: bool,
    current_file_path: String,
    current_function_name: String,
    has_safety_comment: bool,
}

impl<'ast> Visit<'ast> for UnsafeBlockChecker {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if let Expr::Unsafe(unsafe_block) = node {
            // If the unsafe block is found, set the flag to true
            self.has_unsafe = true;

            // Calculate the number of statements in the unsafe block
            let num_stmts = unsafe_block.block.stmts.len();
            
            // Check for complex structures, such as loops and conditionals
            let has_complex_structure = unsafe_block.block.stmts.iter().any(|stmt| {
                matches!(stmt, Stmt::Expr(Expr::If(_) | Expr::While(_) | Expr::ForLoop(_), _))
            });

            // Debug output with additional information
            let output = format!(
                "-----------------------------------------------------------------\n\
                Checking unsafe block with {} statements, complex: {}, name: {}, with_SAFETY_comment: {}, file: {} \n",
                num_stmts,
                has_complex_structure,
                self.current_function_name,
                self.has_safety_comment,
                self.current_file_path,
            );

            // Output to file with lock
            {
                let mut log_file = LOG_FILE.lock().unwrap();
                writeln!(log_file, "{}", output).expect("Failed to write to log file");
            }

            // If the unsafe block contains more than 5 statements or has complex structures, consider it a large unsafe block
            if num_stmts >= 5 || has_complex_structure {
                self.has_large_unsafe = true;
            }
        }
        visit::visit_expr(self, node);
    }

    fn visit_block(&mut self, block: &'ast Block) {
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        match stmt {
            Stmt::Local(local) => self.visit_local(local),
            Stmt::Item(item) => self.visit_item(item),
            Stmt::Expr(expr, _) => self.visit_expr(expr),
            Stmt::Macro(mac) => self.visit_macro(&mac.mac), // Correct usage here
        }
    }
}

/// Scans a Rust source file for functions with unsafe blocks.
fn scan_for_unsafe_blocks(file_path: &str, outputted_functions: &Arc<Mutex<HashSet<String>>>) -> Result<()> {
    let source_code = fs::read_to_string(file_path)?;
    let parsed_file = parse_file(&source_code)?;

    let mut visitor = FunctionVisitor {
        file_path, // Pass the file path to the visitor
        outputted_functions,
    };

    visitor.visit_file(&parsed_file);
    Ok(())
}

/// Processes a directory, scanning all Rust files for unsafe blocks.
fn process_directory(dir_path: &str, outputted_functions: &Arc<Mutex<HashSet<String>>>) -> Result<()> {
    let paths: Vec<_> = fs::read_dir(dir_path)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();

    paths.iter().for_each(|path| {
        if path.is_dir() {
            if let Err(e) = process_directory(path.to_str().unwrap(), outputted_functions) {
                eprintln!("Failed to process directory {}: {}", path.display(), e);
            }
        } else if path.extension().map_or(false, |ext| ext == "rs") {
            let path_display = path.display().to_string();
            
            // Output to console and file with lock
            {
                println!("Processing file: {}", path_display);
                let mut log = LOG_FILE.lock().unwrap();
                writeln!(log, "Processing file: {}", path_display).expect("Failed to write to log file");
            }

            if let Err(e) = scan_for_unsafe_blocks(path.to_str().unwrap(), outputted_functions) {
                eprintln!("Failed to scan file {}: {}", path.display(), e);
            }
        }
    });

    Ok(())
}

// Use a global static mutex for the log file
lazy_static::lazy_static! {
    static ref LOG_FILE: Mutex<File> = Mutex::new(File::create("scan_results.txt").expect("Failed to create log file"));
}

/// Scans for SAFETY comments within a specified line range in a Rust source file.
fn scan_safety_comments(file_path: &str, start_line: usize, end_line: usize) -> bool {
    // Define regular expression for single-line SAFETY comments
    let re_single_line = Regex::new(r"//\s*SAFETY:").unwrap();
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);

    // Process each line in the file
    for (line_number, line) in reader.lines().enumerate() {
        if let Ok(line) = line {
            if line_number + 1 >= start_line && line_number + 1 <= end_line {
                // Check for single-line SAFETY comments
                if re_single_line.is_match(&line) {
                    return true;
                }
            }
        }
    }
    false
}

/// Main function to start scanning the Rust code base for unsafe blocks.
fn main() -> Result<()> {
    let crate_dir = r"overunsafe库"; // Adjust to the directory of your crate

    let outputted_functions = Arc::new(Mutex::new(HashSet::new()));

    process_directory(crate_dir, &outputted_functions)?;

    // Output to console
    println!("Scan results have been written to scan_results.txt");

    Ok(())
}
