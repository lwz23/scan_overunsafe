# scan_overunsafe
这是lwz的rust overunsafe扫描器，可以扫描出给定库文件夹中所有的rs文件，记录出现unsafe代码块的函数名称以及unsafe的指令数量，并且通过扫描rust的ast中unsafe代码块的指令数量以及是否具有复杂结构来决定是否输出它们。接下来的任务：
1. 判断这些unsafe块是否存在安全的替代方案。（未完成）
2. 是否有比unsafe超过5个指令更加合适的判断标准，例如百分比或者调用了unsafe的函数。（未完成）
3. 更多的overunsafe代码库测试。(已完成，存在overunsafe BUG的项目中添加了smallvec库，并且添加了14个当前流行的rust库)
4. 查看更多的overunsafe案例，整理到库中(目标20个，8.5开始)
5. 添加检测//SAFETY注释的功能，如果使用了unsasfe代码但是没有safety注释，则也记录下来。(8.5开始)