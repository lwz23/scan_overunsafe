use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use anyhow::Result;
use syn::Pat;
use syn::{ItemFn, ImplItem, visit::{self, Visit}, parse_file, Attribute, Expr, Block, Stmt};
use quote::quote;
use regex::Regex;

/// Struct to visit functions and methods in the Rust code.
struct FunctionVisitor<'a> {
    file_path: &'a str,
    outputted_functions: &'a Arc<Mutex<HashSet<(String, String)>>>,
    total_functions: &'a Arc<Mutex<usize>>,  // 记录函数总数
    total_unsafe_blocks: &'a Arc<Mutex<usize>>, // 记录 unsafe 代码块总数
    total_no_safety_unsafe_blocks: &'a Arc<Mutex<usize>>, // 记录没有 SAFETY 注释的 unsafe 代码块数量
    total_potential_overunsafe: &'a Arc<Mutex<usize>>, // 记录 Potential Overunsafe 案例数量
    necessary_unsafe: &'a Arc<Mutex<usize>>,  // 记录必要的unsafe代码块数量
}

impl<'a, 'ast> Visit<'ast> for FunctionVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let function_name = node.sig.ident.to_string();
        let unique_key = (function_name.clone(), self.file_path.to_string());

        *self.total_functions.lock().unwrap() += 1; // 记录总函数数

        if !self.is_test_function(&node.attrs)
            && !self.outputted_functions.lock().unwrap().contains(&unique_key)
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
                total_unsafe_blocks: self.total_unsafe_blocks.clone(),
                total_no_safety_unsafe_blocks: self.total_no_safety_unsafe_blocks.clone(),
                has_unrelated_logic: false,
            };

            checker.visit_block(&node.block);

            let is_potential_overunsafe = (checker.has_large_unsafe || checker.has_unrelated_logic) && !checker.has_safety_comment;

            if checker.has_unsafe {
                if is_potential_overunsafe {
                    *self.total_potential_overunsafe.lock().unwrap() += 1; // 更新 Potential Overunsafe 案例数量
                }
            
                if !checker.has_unrelated_logic && !checker.has_large_unsafe {
                    *self.necessary_unsafe.lock().unwrap() += 1; // 更新必要的unsafe代码块数量
                }
            }
            

            // 只在符合潜在overunsafe标准时才打印详细信息
            if is_potential_overunsafe {
                let function_code = quote! {
                    #node
                };
                let formatted_code = prettyplease::unparse(&syn::parse_quote!(#function_code));
                let output = format!(
                    "Found function with unsafe block in {}:\nFile: {}\nStart Line: {}, End Line: {:?}\n{}\n\n",
                    function_name, self.file_path, start_line, end_line, formatted_code
                );

                {
                    let mut log_file = LOG_FILE.lock().unwrap();
                    writeln!(log_file, "{}", output).expect("Failed to write to log file");
                    log_file.flush().expect("Failed to flush log file");
                }
            }

            self.outputted_functions.lock().unwrap().insert(unique_key);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        for item in &node.items {
            if let ImplItem::Fn(method) = item {
                let method_name = method.sig.ident.to_string();
                let unique_key = (method_name.clone(), self.file_path.to_string());

                *self.total_functions.lock().unwrap() += 1; // 记录总函数数

                if !self.is_test_function(&method.attrs)
                    && !self.outputted_functions.lock().unwrap().contains(&unique_key)
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
                        total_unsafe_blocks: self.total_unsafe_blocks.clone(),
                        total_no_safety_unsafe_blocks: self.total_no_safety_unsafe_blocks.clone(),
                        has_unrelated_logic: false,
                    };

                    checker.visit_block(&method.block);

                    let is_potential_overunsafe = (checker.has_large_unsafe || checker.has_unrelated_logic) && !checker.has_safety_comment;

                    if checker.has_unsafe {
                        if is_potential_overunsafe {
                            *self.total_potential_overunsafe.lock().unwrap() += 1; // 更新 Potential Overunsafe 案例数量
                        }
                    
                        if !checker.has_unrelated_logic && !checker.has_large_unsafe {
                            *self.necessary_unsafe.lock().unwrap() += 1; // 更新必要的unsafe代码块数量
                        }
                    }
                    
                    // 只在符合潜在overunsafe标准时才打印详细信息
                    if is_potential_overunsafe {
                        let method_code = quote! {
                            #method
                        };
                        let formatted_code = prettyplease::unparse(&syn::parse_quote!(#method_code));
                        let output = format!(
                            "File: {}\nStart Line: {}, End Line: {:?}\n{}\n\n",
                            self.file_path, start_line, end_line, formatted_code
                        );

                        {
                            let mut log_file = LOG_FILE.lock().unwrap();
                            writeln!(log_file, "{}", output).expect("Failed to write to log file");
                            log_file.flush().expect("Failed to flush log file");
                        }
                    }

                    self.outputted_functions.lock().unwrap().insert(unique_key);
                }
            }
        }
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
    total_unsafe_blocks: Arc<Mutex<usize>>, 
    total_no_safety_unsafe_blocks: Arc<Mutex<usize>>, 
    has_unrelated_logic: bool, 
}

impl<'ast> Visit<'ast> for UnsafeBlockChecker {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if let Expr::Unsafe(unsafe_block) = node {
            self.has_unsafe = true;

            let num_stmts = unsafe_block.block.stmts.len();
            let has_complex_structure = unsafe_block.block.stmts.iter().any(|stmt| {
                matches!(stmt, Stmt::Expr(Expr::If(_) | Expr::While(_) | Expr::ForLoop(_), _))
            });

            // 创建一个集合，用来保存与 unsafe 相关的变量
            let mut unsafe_context_vars = HashSet::new();

            // 先遍历一次所有语句，找到所有定义的变量
            for stmt in &unsafe_block.block.stmts {
                if let Stmt::Local(local) = stmt {
                    if let Pat::Ident(pat_ident) = &local.pat {
                        unsafe_context_vars.insert(pat_ident.ident.to_string());
                    }
                }
            }

            // 检查是否有与 unsafe 操作不相关的逻辑
            for stmt in &unsafe_block.block.stmts {
                if let Stmt::Expr(expr, _) = stmt {
                    if !is_related_to_unsafe(expr, &unsafe_context_vars) {
                        self.has_unrelated_logic = true;
                        break;
                    }
                }
            }

            let output = format!(
                "-----------------------------------------------------------------\n\
                Checking unsafe block with {} statements, With_large_unsafe: {}, Unrelated Logic: {}, With_SAFETY_comment: {}, Name: {},  File: {}\nPotential Overunsafe：{}\n",
                num_stmts,
                self.has_large_unsafe,
                self.has_unrelated_logic,
                self.has_safety_comment,
                self.current_function_name,
                self.current_file_path,
                (self.has_large_unsafe || self.has_unrelated_logic) && !self.has_safety_comment,
            );

            {
                let mut log_file = LOG_FILE.lock().unwrap();
                writeln!(log_file, "{}", output).expect("Failed to write to log file");
                log_file.flush().expect("Failed to flush log file");
            }

            // 判断是否为 large unsafe block
            if num_stmts >= 5 || has_complex_structure {
                self.has_large_unsafe = true;
            }

            *self.total_unsafe_blocks.lock().unwrap() += 1; 
            if !self.has_safety_comment {
                *self.total_no_safety_unsafe_blocks.lock().unwrap() += 1; 
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
            Stmt::Macro(mac) => self.visit_macro(&mac.mac),
        }
    }
}

fn is_related_to_unsafe(expr: &Expr, unsafe_context_vars: &HashSet<String>) -> bool {
    match expr {
        Expr::Call(_) | Expr::MethodCall(_) | Expr::Unsafe(_) => true,
        Expr::Path(ref path) => {
            if let Some(ident) = path.path.get_ident() {
                return unsafe_context_vars.contains(ident.to_string().as_str());
            }
            false
        }
        Expr::Assign(assign) => {
            if let Expr::Path(ref path) = *assign.left {
                if let Some(ident) = path.path.get_ident() {
                    // 检查赋值操作是否影响unsafe上下文变量
                    return unsafe_context_vars.contains(ident.to_string().as_str()) ||
                           is_related_to_unsafe(&assign.right, unsafe_context_vars);
                }
            }
            is_related_to_unsafe(&assign.right, unsafe_context_vars)
        }
        Expr::Binary(binary) => {
            is_related_to_unsafe(&binary.left, unsafe_context_vars) ||
            is_related_to_unsafe(&binary.right, unsafe_context_vars)
        }
        Expr::Unary(unary) => {
            is_related_to_unsafe(&unary.expr, unsafe_context_vars)
        }
        Expr::If(expr_if) => {
            is_related_to_unsafe(&expr_if.cond, unsafe_context_vars) ||
            expr_if.then_branch.stmts.iter().any(|stmt| match stmt {
                Stmt::Expr(expr, _) => is_related_to_unsafe(expr, unsafe_context_vars),
                _ => false,
            }) ||
            expr_if.else_branch.as_ref().map_or(false, |(_, else_expr)| {
                is_related_to_unsafe(else_expr, unsafe_context_vars)
            })
        }
        Expr::Loop(expr_loop) => {
            expr_loop.body.stmts.iter().any(|stmt| match stmt {
                Stmt::Expr(expr, _) => is_related_to_unsafe(expr, unsafe_context_vars),
                _ => false,
            })
        }
        _ => false,
    }
}


fn scan_for_unsafe_blocks(file_path: &str, outputted_functions: &Arc<Mutex<HashSet<(String, String)>>>, total_functions: &Arc<Mutex<usize>>, total_unsafe_blocks: &Arc<Mutex<usize>>, total_no_safety_unsafe_blocks: &Arc<Mutex<usize>>, total_potential_overunsafe: &Arc<Mutex<usize>>, necessary_unsafe: &Arc<Mutex<usize>>) -> Result<()> {
    let source_code = fs::read_to_string(file_path)?;
    let parsed_file = parse_file(&source_code)?;

    let mut visitor = FunctionVisitor {
        file_path,
        outputted_functions,
        total_functions,
        total_unsafe_blocks,
        total_no_safety_unsafe_blocks,
        total_potential_overunsafe,
        necessary_unsafe,
    };

    visitor.visit_file(&parsed_file);
    Ok(())
}

fn process_directory(dir_path: &str, outputted_functions: &Arc<Mutex<HashSet<(String, String)>>>, total_functions: &Arc<Mutex<usize>>, total_unsafe_blocks: &Arc<Mutex<usize>>, total_no_safety_unsafe_blocks: &Arc<Mutex<usize>>, total_potential_overunsafe: &Arc<Mutex<usize>>, necessary_unsafe: &Arc<Mutex<usize>>) -> Result<()> {
    let paths: Vec<_> = fs::read_dir(dir_path)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();

    paths.iter().for_each(|path| {
        if path.is_dir() {
            if let Err(e) = process_directory(path.to_str().unwrap(), outputted_functions, total_functions, total_unsafe_blocks, total_no_safety_unsafe_blocks, total_potential_overunsafe, necessary_unsafe) {
                eprintln!("Failed to process directory {}: {}", path.display(), e);
            }
        } else if path.extension().map_or(false, |ext| ext == "rs") {
            let path_display = path.display().to_string();
            
            {
                println!("Processing file: {}", path_display);
                let mut log = LOG_FILE.lock().unwrap();
                writeln!(log, "Processing file: {}", path_display).expect("Failed to write to log file");
                log.flush().expect("Failed to flush log file");
            }

            if let Err(e) = scan_for_unsafe_blocks(path.to_str().unwrap(), outputted_functions, total_functions, total_unsafe_blocks, total_no_safety_unsafe_blocks, total_potential_overunsafe, necessary_unsafe) {
                eprintln!("Failed to scan file {}: {}", path.display(), e);
            }
        }
    });

    Ok(())
}

lazy_static::lazy_static! {
    static ref LOG_FILE: Mutex<File> = Mutex::new(File::create("scan_results.txt").expect("Failed to create log file"));
}

fn scan_safety_comments(file_path: &str, start_line: usize, end_line: usize) -> bool {
    let re_single_line = Regex::new(r"(?i)//\s*safety:").unwrap(); // (?i) 使匹配大小写不敏感
    let file = File::open(file_path).expect("Failed to open file");
    let reader = BufReader::new(file);

    for (line_number, line) in reader.lines().enumerate() {
        if let Ok(line) = line {
            if line_number + 1 >= start_line && line_number + 1 <= end_line {
                if re_single_line.is_match(&line) {
                    return true;
                }
            }
        }
    }
    false
}


fn main() -> Result<()> {
    let crate_dir = r"overunsafe库\存在overunsafe的rust库";

    let outputted_functions = Arc::new(Mutex::new(HashSet::<(String, String)>::new()));
    let total_functions = Arc::new(Mutex::new(0));
    let total_unsafe_blocks = Arc::new(Mutex::new(0));
    let total_no_safety_unsafe_blocks = Arc::new(Mutex::new(0));
    let total_potential_overunsafe = Arc::new(Mutex::new(0)); // 新增
    let necessary_unsafe = Arc::new(Mutex::new(0)); // 新增

    process_directory(crate_dir, &outputted_functions, &total_functions, &total_unsafe_blocks, &total_no_safety_unsafe_blocks, &total_potential_overunsafe, &necessary_unsafe)?;

    let total_functions = *total_functions.lock().unwrap();
    let total_unsafe_blocks = *total_unsafe_blocks.lock().unwrap();
    let total_no_safety_unsafe_blocks = *total_no_safety_unsafe_blocks.lock().unwrap();
    let total_potential_overunsafe = *total_potential_overunsafe.lock().unwrap();
    let necessary_unsafe = *necessary_unsafe.lock().unwrap(); // 新增

    let unsafe_function_ratio = if total_functions > 0 {
        (total_unsafe_blocks as f64 / total_functions as f64) * 100.0
    } else {
        0.0
    };
    let nocommit_unsafe_function_ratio = if total_functions > 0 {
        (total_no_safety_unsafe_blocks as f64 / total_functions as f64) * 100.0
    } else {
        0.0
    };
    let nur = if total_unsafe_blocks > 0 {
        (total_no_safety_unsafe_blocks as f64 / total_unsafe_blocks as f64) * 100.0
    } else {
        0.0
    };
    let potential_overunsafe_ratio = if total_functions > 0 {
        (total_potential_overunsafe as f64 / total_functions as f64) * 100.0
    } else {
        0.0
    };
    let necessary_unsafe_ratio = if total_functions > 0 {
        (necessary_unsafe as f64 / total_functions as f64) * 100.0
    } else {
        0.0
    };

    {
        let mut log_file = LOG_FILE.lock().unwrap();
        writeln!(log_file, "\n--- Summary ---").expect("Failed to write to log file");
        writeln!(log_file, "Total functions: {}", total_functions).expect("Failed to write to log file");
        writeln!(log_file, "Total unsafe blocks: {}", total_unsafe_blocks).expect("Failed to write to log file");
        writeln!(log_file, "Total unsafe blocks without SAFETY comment: {}", total_no_safety_unsafe_blocks).expect("Failed to write to log file");
        writeln!(log_file, "Total Potential Overunsafe function: {}", total_potential_overunsafe).expect("Failed to write to log file");
        writeln!(log_file, "Total Necessary Unsafe function: {}", necessary_unsafe).expect("Failed to write to log file");
        writeln!(log_file, "Inner Unsafe function ratio: {:.2}%", unsafe_function_ratio).expect("Failed to write to log file");
        writeln!(log_file, "Inner Unsafe function Without //SAFETY ratio: {:.2}%", nocommit_unsafe_function_ratio).expect("Failed to write to log file");
        writeln!(log_file, "Inner Unsafe function Without //SAFETY and total Inner Unsafe function ratio: {:.2}%", nur).expect("Failed to write to log file");
        writeln!(log_file, "Potential Overunsafe function ratio: {:.2}%", potential_overunsafe_ratio).expect("Failed to write to log file"); // 新增
        writeln!(log_file, "Necessary Unsafe function ratio: {:.2}%", necessary_unsafe_ratio).expect("Failed to write to log file"); // 新增
        log_file.flush().expect("Failed to flush log file");
    }

    println!("Scan results have been written to scan_results.txt");

    Ok(())
}
