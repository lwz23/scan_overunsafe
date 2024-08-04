use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use syn::{ItemFn, ImplItem, visit::{self, Visit}, parse_file, Attribute, Expr, Block, Stmt};
use quote::quote;

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
            && contains_large_unsafe_block(&node.block, &function_name, self.file_path)
        {
            let function_code = quote! {
                #node
            };
            let formatted_code = prettyplease::unparse(&syn::parse_quote!(#function_code));
            let output = format!(
                "Found function with large unsafe block in {}:\nFile: {}\n{}\n\n",
                function_name, self.file_path, formatted_code
            );

            // Output to file with lock
            {
                let mut log_file = LOG_FILE.lock().unwrap();
                writeln!(log_file, "{}", output).expect("Failed to write to log file");
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
                    && contains_large_unsafe_block(&method.block, &method_name, self.file_path)
                {
                    let method_code = quote! {
                        #method
                    };
                    let formatted_code = prettyplease::unparse(&syn::parse_quote!(#method_code));
                    let output = format!(
                        "Found method with large unsafe block in {}:\nFile: {}\n{}\n\n",
                        method_name, self.file_path, formatted_code
                    );

                    // Output to file with lock
                    {
                        let mut log_file = LOG_FILE.lock().unwrap();
                        writeln!(log_file, "{}", output).expect("Failed to write to log file");
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

/// Determines if a function body or method body contains a large unsafe block.
fn contains_large_unsafe_block(block: &Block, name: &str, file_path: &str) -> bool {
    let mut checker = UnsafeBlockChecker { 
        has_large_unsafe: false,
        current_function_name: name.to_string(),
        current_file_path: file_path.to_string(),
    };
    checker.visit_block(block);
    
    checker.has_large_unsafe
}

/// UnsafeBlockChecker is responsible for detecting unsafe blocks within code.
struct UnsafeBlockChecker {
    has_large_unsafe: bool,
    current_file_path: String,
    current_function_name: String,
}

impl<'ast> Visit<'ast> for UnsafeBlockChecker {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if let Expr::Unsafe(unsafe_block) = node {
            // Calculate the number of statements in the unsafe block
            let num_stmts = unsafe_block.block.stmts.len();
            
            // Check for complex structures, such as loops and conditionals
            let has_complex_structure = unsafe_block.block.stmts.iter().any(|stmt| {
                matches!(stmt, Stmt::Expr(Expr::If(_) | Expr::While(_) | Expr::ForLoop(_), _))
            });

            // Debug output with additional information
            let output = format!(
                "-----------------------------------------------------------------\n\
                Checking unsafe block with {} statements, complex: {}, name: {}, file: {}\n",
                num_stmts,
                has_complex_structure,
                self.current_function_name,
                self.current_file_path
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

/// Scans a Rust source file for functions with large unsafe blocks.
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

/// Processes a directory, scanning all Rust files for large unsafe blocks.
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

/// Main function to start scanning the Rust code base for large unsafe blocks.
fn main() -> Result<()> {
    let crate_dir = r"C:\Users\ROG\Desktop\overunsafe库"; // Adjust to the directory of your crate

    let outputted_functions = Arc::new(Mutex::new(HashSet::new()));

    process_directory(crate_dir, &outputted_functions)?;

    // Output to console
    println!("Scan results have been written to scan_results.txt");

    Ok(())
}
