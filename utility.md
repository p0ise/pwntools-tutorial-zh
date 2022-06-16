目录
=================

  * [实用函数](#实用函数)
    * [打包和解包整数](#打包和解包整数)
    * [文件 I/O](#文件 I/O)
    * [散列（哈希）和编码](#散列（哈希）和编码)
        * [Base64](#base64)
        * [散列（哈希）](#散列（哈希）)
        * [URL 编码](#URL 编码)
        * [十六进制编码](#十六进制编码)
        * [位操作和十六进制转储](#位操作和十六进制转储)
        * [十六进制转储](#十六进制转储)
    * [模式生成](#模式生成)

# 实用函数

Pwntools 有一半左右的内容都是实用函数集合，让你能不再需要来回复制这样的代码：

```py
import struct

def p(x):
    return struct.pack('I', x)
def u(x):
    return struct.unpack('I', x)[0]

1234 == u(p(1234))
```

Instead, you just get nice little wrappers.  As an added bonus, everything is a bit more legible and easier to understand when reading someone else's exploit code.

相反，你只需要使用这些漂亮简洁的封装。这还能使理解其他人写的漏洞利用代码更加容易。 

```py
from pwn import *

1234 == unpack(pack(1234))
```

## 打包和解包整数

这可能是你会做的最常见的事情，所以它写在最上面。主要的`pack`和 `unpack`函数默认使用全局设置 [`context`](https://github.com/Gallopsled/pwntools-tutorial/blob/master/context.md)如 `endian`,  `bits`， 和 `sign`。

你也可以在函数调用中明确指定它们。 

```py
pack(1)
# '\x01\x00\x00\x00'

pack(-1)
# '\xff\xff\xff\xff'

pack(2**32 - 1)
# '\xff\xff\xff\xff'

pack(1, endian='big')
# '\x00\x00\x00\x01'

p16(1)
# '\x01\x00'

hex(unpack('AAAA'))
# '0x41414141'

hex(u16('AA'))
# '0x4141'
```

## 文件 I/O

一个函数调用，它会做你想做的事。 

```py
from pwn import *

write('filename', 'data')
read('filename')
# 'data'
read('filename', 1)
# 'd'
```

## 散列（哈希）和编码

快捷地使用函数将你的数据转换为需要的任何格式。 

#### Base64

```py
'hello' == b64d(b64e('hello'))
```

#### 散列（哈希）

```py
md5sumhex('hello') == '5d41402abc4b2a76b9719d911017c592'
write('file', 'hello')
md5filehex('file') == '5d41402abc4b2a76b9719d911017c592'
sha1sumhex('hello') == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
```

#### URL 编码

```py
urlencode("Hello, World!") == '%48%65%6c%6c%6f%2c%20%57%6f%72%6c%64%21'
```

#### 十六进制编码

```py
enhex('hello')
# '68656c6c6f'
unhex('776f726c64')
# 'world'
```

#### 位操作和十六进制转储

```py
bits(0b1000001) == bits('A')
# [0, 0, 0, 1, 0, 1, 0, 1]
unbits([0,1,0,1,0,1,0,1])
# 'U'
```

#### 十六进制转储

```py
print hexdump(read('/dev/urandom', 32))
# 00000000  65 4c b6 62  da 4f 1d 1b  d8 44 a6 59  a3 e8 69 2c  │eL·b│·O··│·D·Y│··i,│
# 00000010  09 d8 1c f2  9b 4a 9e 94  14 2b 55 7c  4e a8 52 a5  │····│·J··│·+U|│N·R·│
# 00000020
```

## 模式生成

模式生成是一种非常方便的查找偏移量的方法，无需进行数学运算。 

假设我们有一个直接的缓冲区溢出，我们生成一个模式并将其提供给目标应用程序。 

```py
io = process(...)
io.send(cyclic(512))
```

在核心转储中，我们可能会看到崩溃发生在 0x61616178。  我们可以避免需要对崩溃框架进行的任何分析，而只需通过那个数字来获得一个偏移量。 

```py
cyclic_find(0x61616178)
# 92
```
