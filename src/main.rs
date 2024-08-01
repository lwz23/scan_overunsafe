use regex::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use anyhow::Result;
use syn::{ItemFn, ImplItem, visit::{self, Visit}, parse_file, Attribute};
use quote::quote;

struct FunctionVisitor<'a> {
    target_fn_name: &'a str,
    found: bool,
    outputted_functions: &'a mut HashSet<String>,
}

impl<'a, 'ast> Visit<'ast> for FunctionVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if node.sig.ident == self.target_fn_name && !self.is_test_function(&node.attrs) && !self.outputted_functions.contains(self.target_fn_name) {
            let function_code = quote! {
                #node
            };
            let formatted_code = prettyplease::unparse(&syn::parse_quote!(#function_code));
            println!("{}", formatted_code);
            self.outputted_functions.insert(self.target_fn_name.to_string());
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        for item in &node.items {
            if let ImplItem::Fn(method) = item {
                if method.sig.ident == self.target_fn_name && !self.is_test_function(&method.attrs) && !self.outputted_functions.contains(self.target_fn_name) {
                    let method_code = quote! {
                        #method
                    };
                    let formatted_code = prettyplease::unparse(&syn::parse_quote!(#method_code));
                    println!("{}", formatted_code);
                    self.outputted_functions.insert(self.target_fn_name.to_string());
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

fn scan_for_unsafe_blocks(file_path: &str, unsafe_re: &Regex, function_re: &Regex, outputted_functions: &mut HashSet<String>) -> Result<()> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut inside_unsafe_block = false;
    let mut line_number = 0;
    let mut unsafe_block_lines = vec![];
    let mut current_function = String::new();

    for line in reader.lines() {
        line_number += 1;
        let line = line?;

        // Check for function definition
        if let Some(caps) = function_re.captures(&line) {
            current_function = caps.get(1).map_or(String::new(), |m| m.as_str().to_string());
        }

        // Check for start of unsafe block
        if unsafe_re.is_match(&line) {
            inside_unsafe_block = true;
            unsafe_block_lines.push((line_number, line.to_string())); // Clone the line content
        } else if inside_unsafe_block {
            unsafe_block_lines.push((line_number, line.to_string())); // Clone the line content
            // Check for end of unsafe block
            if line.trim().ends_with('}') {
                if unsafe_block_lines.len() > 5 {
                    println!("-------------------------------------------------------------------------------");
                    println!("File: {}", file_path);
                    println!("Function: {}", current_function);

                    let source_code = fs::read_to_string(file_path).expect("Failed to read file");
                    let parsed_file = parse_file(&source_code).expect("Failed to parse file");

                    let mut visitor = FunctionVisitor {
                        target_fn_name: &current_function,
                        found: false,
                        outputted_functions,
                    };
                    visitor.visit_file(&parsed_file);

                    println!("Unsafe Starting line: {}", unsafe_block_lines[0].0);
                    println!("Unsafe block content:");
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

fn process_directory(dir_path: &str, unsafe_re: &Regex, function_re: &Regex, outputted_functions: &mut HashSet<String>) -> Result<()> {
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            process_directory(path.to_str().unwrap(), unsafe_re, function_re, outputted_functions)?;
        } else if path.extension().map_or(false, |ext| ext == "rs") {
            println!("Processing file: {}", path.display());
            scan_for_unsafe_blocks(path.to_str().unwrap(), unsafe_re, function_re, outputted_functions)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let crate_dir = r"C:\Users\ROG\Desktop\overunsafe库\rust-stackvector-d0382d5ef903fc96bdcc08c02e36e6dd2eda11a5"; // Adjust to the directory of your crate

    let unsafe_re = Regex::new(r"^\s*unsafe\s*\{")?;
    let function_re = Regex::new(r"^\s*(?:pub\s+)?(?:fn|impl)\s+(\w+)")?;
    
    let mut outputted_functions = HashSet::new();
    process_directory(crate_dir, &unsafe_re, &function_re, &mut outputted_functions)?;

    Ok(())
}
