目录
=================

  * [上下文](#上下文)
    * [上下文设置项](#上下文设置项)
      * [arch](#arch)
      * [bits](#bits)
      * [binary](#binary)
      * [endian](#endian)
      * [log_file](#log_file)
      * [log_level](#log_level)
      * [sign](#sign)
      * [terminal](#terminal)
      * [timeout](#timeout)
      * [update](#update)

# 上下文

 `context` 对象是一个全局的、线程感知的对象，其中包含 `pwntools` 使用的多个设置项。 

通常在 exp 的顶部，你会发现如下内容： 

```py
from pwn import *
context.arch = 'amd64'
```

它告诉 pwntools 生成的 shellcode 将用于 `amd64` 平台，并且默认字长为 64 位 。

## 上下文设置项

### arch

目标架构。有效值为 `"aarch64"`,  `"arm"`,  `"i386"`,  `"amd64"`等。默认为 `"i386"`。

第一次设置此项时，它会同时自动设置 `context.bits` 和 `context.endian` 为最可能的值。 

### bits

目标二进制中由多少位组成一个字，例如 32 或 64。 

### binary

从 ELF 文件中获取设置。 例如， `context.binary='/bin/sh'`。

### endian

字节序，根据需要设置成 `"big"`（大端序）或者 `"little"`（默认，小端序）。 

### log_file

用于输出日志记录的文件。 

### log_level

日志的详细程度。  有效值是整数（越小越详细），或字符串值如 `"debug"`、 `"info"` 和 `"error"`。

### sign

设置整数打包/解包的默认符号类型。 默认为 `"unsigned"`. 

### terminal

用于打开新窗口的首选终端程序。  默认情况下，使用 `x-terminal-emulator`或者 `tmux`. 

### timeout

tube 操作的默认超时时间。 

### update

用于一次设置多个值，例如 `context.update(arch='mips', bits=64, endian='big')`。
