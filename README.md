# scan_overunsafe

这是 lwz 的 Rust overunsafe 扫描器，可以扫描出给定库文件夹中所有的 `.rs` 文件。

## 输出形式：
1. 对于所有包含 `unsafe` 代码块的函数，会输出含有 `unsafe block` 函数的信息，如下：
   ```
   Checking unsafe block with 1 statements, complex: false, name: in_parallel_with_slice, with_SAFETY_comment: true, file: overunsafe库\存在overunsafe的rust库\gitoxide-a807dd1ffb05efd177700d065095249e6c4b3c68\gix-features\src\parallel\in_parallel.rs
   ```
2. 对于具有 large `unsafe block` 或者使用了 `unsafe block` 却没有书写 `// SAFETY` 注释的函数，会输出更加详细的信息，如下：
   ```
   Checking unsafe block with 3 statements, complex: false, name: extend, with_SAFETY_comment: false, file: overunsafe库\存在overunsafe的rust库\rust-smallvec-19de50108d403efaa7cd979eac3bb97a4432fd4b\lib.rs

   Found method with unsafe block in extend:
   File: overunsafe库\存在overunsafe的rust库\rust-smallvec-19de50108d403efaa7cd979eac3bb97a4432fd4b\lib.rs
   Start Line: 1345, End Line: 1366
   fn extend<I: IntoIterator<Item = A::Item>>(&mut self, iterable: I) {
       let mut iter = iterable.into_iter();
       let (lower_size_bound, _) = iter.size_hint();
       self.reserve(lower_size_bound);
       unsafe {
           let (ptr, len_ptr, cap) = self.triple_mut();
           let mut len = SetLenOnDrop::new(len_ptr);
           while len.get() < cap {
               if let Some(out) = iter.next() {
                   ptr::write(ptr.offset(len.get() as isize), out);
                   len.increment_len(1);
               } else {
                   break;
               }
           }
       }
       for elem in iter {
           self.push(elem);
       }
   }
   ```

## 接下来的任务：
1. 是否有比 `unsafe` 超过 5 个指令更加合适的判断标准，例如百分比或者调用了 `unsafe` 的函数。（已完成，目前使用的是 large `unsafe` 和 `// SAFETY` 注释共同检测的标准）
2. 更多的 overunsafe 代码库测试。（已完成，存在 overunsafe BUG 的项目中添加了 smallvec 库，并且添加了 14 个当前流行的 Rust 库）
3. 添加检测 `//SAFETY` 注释的功能，如果使用了 `unsafe` 代码但是没有 `//SAFETY` 注释，则也记录下来。（已完成）
4. 查看更多的 overunsafe 案例，整理到库中（目标 20 个，8.5 开始）
5. 判断这些 `unsafe` 块是否存在安全的替代方案。（未完成）
