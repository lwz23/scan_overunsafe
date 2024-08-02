# scan_overunsafe
这是lwz的rust overunsafe扫描器，可以扫描出给定库文件夹中所有的rs文件，记录出现unsafe代码块的函数名称以及unsafe的指令数量，并且通过扫描rust的ast中unsafe代码块的指令数量以及是否具有复杂结构来决定是否输出它们。接下来的任务：
1. 判断这些unsafe块是否存在安全的替代方案。（未完成）
2. 是否有比unsafe超过5个指令更加合适的判断标准，例如百分比或者调用了unsafe的函数。（未完成）
3. 更多的overunsafe代码库测试。(已完成，添加了smallvec库)
4. 发现processing file和下面关于unsafe的输出信息错位，不方便确认位置，8.3修复它（未完成）