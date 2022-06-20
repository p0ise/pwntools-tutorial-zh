目录
=================

  * [汇编](#汇编)
    * [基础汇编](#基础汇编)
    * [封装好的汇编（`shellcraft`）](#封装好的汇编shellcraft)
    * [命令行工具](#命令行工具)
      * [asm ](#asm)
      * [disasm ](#disasm)
      * [shellcraft ](#shellcraft)
    * [其他架构](#其他架构)
      * [封装好的汇编](#封装好的汇编)
      * [命令行工具](#命令行工具-1)

# 汇编

Pwntools 使得在几乎任何架构中执行汇编变得非常容易，并附带了各种经过封装但可定制的 shellcode，可以开箱即用。 

在里面 [`walkthrough`](https://github.com/Gallopsled/pwntools-tutorial/blob/master/walkthrough)目录，有几个较长的shellcode教程。  此页面为你提供基础知识。 

## 基础汇编

最基础的例子，就是将汇编转换成 shellcode。 

```py
from pwn import *

print repr(asm('xor edi, edi'))
# '1\xff'

print enhex(asm('xor edi, edi'))
# 31ff
```

## 封装好的汇编（`shellcraft`）

`shellcraft` 模块为您提供预封装好的汇编指令。它通常是可定制的。找出哪个`shellcraft`模板存在的最简单的方法就是看 [RTD上的文档 ](https://pwntools.readthedocs.org/en/latest/shellcraft.html)。

```py
from pwn import *
help(shellcraft.sh)
print '---'
print shellcraft.sh()
print '---'
print enhex(asm(shellcraft.sh()))
```
```
Help on function sh in module pwnlib.shellcraft.internal:

sh()
    Execute /bin/sh
---
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f

    /* call execve('esp', 0, 0) */
    push (SYS_execve) /* 0xb */
    pop eax
    mov ebx, esp
    xor ecx, ecx
    cdq /* edx=0 */
    int 0x80
---
6a68682f2f2f73682f62696e6a0b5889e331c999cd80
```

## 命令行工具

这有三个用于与汇编指令交互的命令行工具： 

- `asm`
- `disasm`
- `shellcraft`

### `asm`

asm 工具实现的功能正如它的名称那样（does what it says on the tin）。它提供了几个用于格式化输出的选项。当输出为终端时，默认为十六进制编码。

```
$ asm nop
90
```

当输出是其他内容时，它会写入原始数据。 

```
$ asm nop | xxd
0000000: 90                                       .
```

如果命令行上没有提供指令，它会从标准输入上获取数据。 

```
$ echo 'push ebx; pop edi' | asm
535f
```

Finally, it supports a few different options for specifying the output format, via the `--format` option.  Supported arguments are `raw`, `hex`, `string`, and `elf`.

最后，它支持几个不同的选项来指定输出格式，通过 `--format` 选项。支持的参数是 `raw`、`hex`、`string` 和 `elf` 。

```
$ asm --format=elf 'int3' > ./int3
$ ./halt
Trace/breakpoint trap (core dumped)
```

### `disasm`

Disasm 是 `asm` 的逆过程。

```
$ disasm cd80
   0:    cd 80                    int    0x80
$ asm nop | disasm
   0:    90                       nop
```

### `shellcraft`

 `shellcraft` 命令是内部 `shellcraft` 模块的命令行接口。在命令行上，必须按 `arch.os.template` 的顺序指定完整的上下文。

```
$ shellcraft i386.linux.sh
6a68682f2f2f73682f62696e6a0b5889e331c999cd80
```

## 其他架构

为其他架构汇编需要你安装一个合适版本的 `binutils`。您应该查看 [installing.md ](https://github.com/Gallopsled/pwntools-tutorial/blob/master/installing.md)以获取更多信息。唯一需要的更改是在全局上下文变量中设置架构。你可以在 [context.md ](https://github.com/Gallopsled/pwntools-tutorial/blob/master/context.md)中看到更多关于 `context` 的内容。 

```py
from pwn import *

context.arch = 'arm'

print repr(asm('mov r0, r1'))
# '\x01\x00\xa0\xe1'

print enhex(asm('mov r0, r1'))
# 0100a0e1
```

### 封装好的汇编

`shellcraft` 模块会自动切换到适当的架构。 

```py
from pwn import *

context.arch = 'arm'

print shellcraft.sh()
print enhex(asm(shellcraft.sh()))
```
```
    adr r0, bin_sh
    mov r2, #0
    mov r1, r2
    svc SYS_execve
bin_sh: .asciz "/bin/sh"

08008fe20020a0e30210a0e10b0000ef2f62696e2f736800
```

### 命令行工具

你也可以通过 `--context` 命令行选项来使用命令行组装其他架构的 shellcode。 

```
$ asm --context=arm 'mov r0, r1'
0100a0e1
$ shellcraft arm.linux.sh
08008fe20020a0e30210a0e10b0000ef2f62696e2f736800
```
