# Pwntools 教程

本仓库包含一些 pwntools 入门的基础教程。

这些教程不会解释提到的逆向工程或漏洞利用的相关术语，而是假设你已经知晓这些知识。 

# 介绍

[`Pwntools`](https://pwntools.com)是一个工具包，用于 CTF 中的漏洞利用尽可能轻松，并使 exp 尽可能易于阅读。 

有些代码每个人都写了一百万次，每个人都有自己的方式。 Pwntools 旨在以半标准的方式提供所有这些，以便你可以停止复制粘贴相同的`struct.unpack('>I', x)`代码，而去使用更易读的包装器，例如 `pack`或者 `p32`甚至 `p64(..., endian='big', sign=True)`. 

除了围绕普通功能的便利包装器之外，它还提供了一组非常丰富的 `tubes`，这些 `tubes` 能够将你将执行的所有 IO 包装在一个统一的接口中。从而让本地漏洞利用到远程漏洞利用或通过 SSH 进行的本地利用之间的切换只需要更改一行代码。 

最后但并非最不重要的一点是，它还包括用于中高级用例的各种利用辅助工具。 这些包括给定内存泄露术语的远程符号解析（ `MemLeak`和 `DynELF`）、ELF 解析和修复，以及 ROP 片段发现和调用链构建。

# 目录

- [安装 Pwntools](installing.md)
- [管（Tubes）](tubes.md)
  
    + 基本管（Tubes）
    + 交互式Shell
    + 进程
    + 网络
    + Secure Shell（SSH）
    + 串口
- [实用函数](utility.md)
  
    + 编码和散列（哈希）
    + 打包 / 解包整数
    + 模式生成
    + 安全评估
- [Bytes vs. Strings](bytes.md)
  
    + Python2
    - Python3
        + 陷阱（Gotchas）
- [上下文](context.md)
  
    + 架构
    + 字节序
    + 日志详细程度
    + 超时
- [ELFs](elf.md)
    + 读写
    + 修补（Patching）
    + 符号
- [汇编](assembly.md)
  
    + 汇编 shellcode
    + 反汇编字节码
    + Shellcraft 库
    + 常量
- [调试](debugging.md)
    
    + 调试本地进程
    + 在入口点设置断点
    + 调试shellcode
- [ROP](rop.md)
    + Dumping gadgets
    + Searching for gadgets
    + ROP stack generation
    + Helper functions
- [Logging](logging.md)
    + Basic logging
    + Log verbosity
    + Progress spinners
- [Leaking Remote Memory](leaking.md)
    + Declaring a leak function
    + Leaking arbitrary memory
    + Remote symbol resolution
