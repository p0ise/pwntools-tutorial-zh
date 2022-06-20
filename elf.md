目录
=================

  * [ELFs](#elfs)
    * [加载 ELF 文件](#加载-ELF-文件)
    * [使用符号](#使用符号)
    * [更改基地址](#更改基地址)
    * [读取 ELF 文件](#读取-ELF-文件)
    * [修补 ELF 文件（Patching）](#修补-ELF-文件Patching)
    * [搜索 ELF 文件](#搜索-ELF-文件)
    * [构建 ELF 文件 ](#构建-ELF-文件 )
    * [运行和调试 ELF 文件 ](#运行和调试-ELF-文件 )

# ELFs

Pwntools 通过 `ELF` 类与 ELF 文件相对直接地进行交互。 你可以在 [RTD](https://pwntools.readthedocs.org/en/latest/elf.html) 上找到完整的文档。 

## 加载 ELF 文件

ELF 文件通过路径加载。加载完成后，会打印一些有关文件的安全相关属性。 

```py
from pwn import *

e = ELF('/bin/bash')
# [*] '/bin/bash'
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      No PIE
#     FORTIFY:  Enabled
```

## 使用符号 

ELF 文件有几组不同的可用符号，每一个都包含在一个`{name: data}`字典中。

- `ELF.symbols` 列出所有已知符号，包括下面这些符号。 其中，PLT 条目优先于 GOT 条目。 
- `ELF.got` 仅包含 GOT 条目。
- `ELF.plt` 仅包含 PLT 条目。
- `ELF.functions` 仅包含函数（需要 DWARF 符号）。

这能避免对地址进行硬编码，从而有利于保持 exp 的鲁棒性。 

```py
from pwn import *

e = ELF('/bin/bash')

print "%#x -> license" % e.symbols['bash_license']
print "%#x -> execve" % e.symbols['execve']
print "%#x -> got.execve" % e.got['execve']
print "%#x -> plt.execve" % e.plt['execve']
print "%#x -> list_all_jobs" % e.functions['list_all_jobs'].address
```

这将打印如下内容： 

```
0x4ba738 -> license
0x41db60 -> execve
0x6f0318 -> got.execve
0x41db60 -> plt.execve
0x446420 -> list_all_jobs
```

## 更改基地址

更改 ELF 文件的基地址（例如调整 ASLR）非常简单。  让我们改变 `bash` 的基地址，并查看所有符号的变化。

```py
from pwn import *

e = ELF('/bin/bash')

print "%#x -> base address" % e.address
print "%#x -> entry point" % e.entry
print "%#x -> execve" % e.symbols['execve']

print "---"
e.address = 0x12340000

print "%#x -> base address" % e.address
print "%#x -> entry point" % e.entry
print "%#x -> execve" % e.symbols['execve']
```

这应该打印如下内容： 

```
0x400000 -> base address
0x42020b -> entry point
0x41db60 -> execve
---
0x12340000 -> base address
0x1236020b -> entry point
0x1235db60 -> execve
```

## 读取 ELF 文件 

我们可以像被加载到内存中一样直接与 ELF 交互，使用 `read`、`write`和在 `packing` 模块命名的其他函数。 此外，你可以通过 `disasm`方法查看反汇编。

```py
from pwn import *

e = ELF('/bin/bash')

print repr(e.read(e.address, 4))

p_license = e.symbols['bash_license']
license   = e.unpack(p_license)
print "%#x -> %#x" % (p_license, license)

print e.read(license, 14)
print e.disasm(e.symbols['main'], 12)
```

这会打印出类似这样的内容： 

```
'\x7fELF'
0x4ba738 -> 0x4ba640
License GPLv3+
  41eab0:       41 57                   push   r15
  41eab2:       41 56                   push   r14
  41eab4:       41 55                   push   r13
```

## 修补 ELF 文件（Patching）

修补（Patching） ELF 文件同样简单。 

```py
from pwn import *

e = ELF('/bin/bash')

# Cause a debug break on the 'exit' command
e.asm(e.symbols['exit_builtin'], 'int3')

# Disable chdir and just print it out instead
e.pack(e.got['chdir'], e.plt['puts'])

# Change the license
p_license = e.symbols['bash_license']
license = e.unpack(p_license)
e.write(license, 'Hello, world!\n\x00')

e.save('./bash-modified')
```

然后我们可以运行修改后的 bash。 

```
$ chmod +x ./bash-modified
$ ./bash-modified -c 'exit'
Trace/breakpoint trap (core dumped)
$ ./bash-modified --version | grep "Hello"
Hello, world!
$ ./bash-modified -c 'cd "No chdir for you!"'
/home/user/No chdir for you!
No chdir for you!
./bash-modified: line 0: cd: No chdir for you!: No such file or directory
```

## 搜索 ELF 文件 

你经常需要查找一些字节序列。最常见的例子是搜索例如 `"/bin/sh\x00"`用来调用 `execve`。 `search` 方法返回一个迭代器，允许你获取第一个结果，或者继续搜索你需要的一些特殊的东西（例如地址中没有坏字符）。你可以选择向`search` 传递 `writable` 参数，来指明它应该只返回可写段中的地址。

```py
from pwn import *

e = ELF('/bin/bash')

for address in e.search('/bin/sh\x00'):
    print hex(address)
```

上面的示例打印如下内容： 

```
0x420b82
0x420c5e
```

## 构建 ELF 文件 

ELF 文件可以相对容易地从头开始创建。所有功能都是上下文感知的。相关的功能有 `from_bytes`和 `from_assembly`。每个返回一个 `ELF`对象，可以很容易地保存到文件中。 

```
from pwn import *

ELF.from_bytes('\xcc').save('int3-1')
ELF.from_assembly('int3').save('int3-2')
ELF.from_assembly('nop', arch='powerpc').save('powerpc-nop')
```

## 运行和调试 ELF 文件 

如果你有一个 `ELF`对象，你可以直接运行或调试它。 以下是等价的：

```py
>>> io = elf.process()
# vs
>>> io = process(elf.path)
```

同样，你可以启动一个调试器，来简单地附加到你的 ELF 上。而不需要 C 包装器来加载和调试它，这在测试 shellcode 时非常有用。

```py
>>> io = elf.debug()
# vs
>>> io = gdb.debug(elf.path)
```