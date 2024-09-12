# scan_overunsafe

## 项目简介

这是一个用于扫描 Rust 代码库中潜在overunsafe代码块的工具。它通过解析 Rust 源代码文件，检查函数和方法中是否包含overunsafe代码块，并识别出潜在的overunsafe使用情况。

## 功能特性

- **扫描unsafe代码块**：识别代码中的unsafe块，并检查这些块中是否包含特定的函数调用。
- **识别潜在overunsafe使用**：如果"ptr::copy","set_len"这些函数被调用，则认为该代码块可能是overunsafe的，并输出相关信息。
- **统计信息**：记录了代码库中的函数总数、unsafe代码块总数、没有SAFETY注释的unsafe代码块数量以及潜在的overunsafe使用情况数量。


## 输出结果

- 扫描结果将保存在 `scan_results.txt` 文件中。


