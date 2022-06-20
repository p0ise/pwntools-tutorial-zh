# Bytes vs. Strings

大约十年前，当 Pwntools 最初（重新）编写的时候，Python2 是非常出色的（the bee's knees）。 

```
commit e692277db8533eaf62dd3d2072144ccf0f673b2e
Author: Morten Brøns-Pedersen <mortenbp@gmail.com>
Date:   Thu Jun 7 17:34:48 2012 +0200

    ALL THE THINGS
```

多年来用 Python 编写的许多漏洞利用假设 `str` 对象和 `bytes` 对象是一一对应的，因为这就是 Python2 上字符串的运行原理 ™️ （How Things Work™️）。 在本节中，我们将讨论在 Python3 相对于 Python2 编写漏洞利用程序所需的一些更改。 

## Python2

在 Python2 中， `str` 类和 `bytes` 类从字面上看是同一个类，并且存在 1:1 映射关系。 永远不需要在任何东西上调用 `encode` 或者 `decode` ——文本就是字节，字节就是文本。 

这对于编写漏洞利用非常方便，因为你只需编写 `"\x90\x90\x90\x90"` 就能得到一个 NOP Sled。 Python2 上的所有 Pwntools 管和数据操作都支持字符串或字节。

从来没有人用过 `unicode` 对象来编写漏洞利用，因此 unicode 到字节的转换极为罕见。 

## Python3

在 Python3 中， `unicode` 类实际上是 `str` 类。这有一些直接和明显的后果。 

乍一看，Python3 似乎让事情变得更麻烦了，因为 `bytes` 声明独立的八位字节（用名称 `bytes` 表示），而 `str` 用于任何基于文本的数据表示。 

Pwntools 竭尽全力遵循“最不意外原则”——也就是说，事情会按照你期望的方式运行。 

```
>>> r.send('❤️')
[DEBUG] Sent 0x6 bytes:
    00000000  e2 9d a4 ef  b8 8f                                  │····│··│
    00000006
>>> r.send('\x00\xff\x7f\x41\x41\x41\x41')
[DEBUG] Sent 0x7 bytes:
    00000000  00 ff 7f 41  41 41 41                               │···A│AAA│
    00000007
```

但是，有时也会有点问题。 请注意此处 99f7e2 被转换成了 c299c3b7c3a2。 

```
>>> shellcode = "\x99\xf7\xe2"
>>> print(hexdump(flat("padding\x00", shellcode)))
00000000  70 61 64 64  69 6e 67 00  c2 99 c3 b7  c3 a2        │padd│ing·│····│··│
0000000e
```

发生这种情况是因为文本字符串“\x99\xf7\xe2”会自动转换为 UTF-8 编码点。这可能不是编写者想要的。 

相反，考虑使用 `b` 前缀： 

```
>>> shellcode = b"\x99\xf7\xe2"
>>> print(hexdump(flat(b"padding\x00", shellcode)))
00000000  70 61 64 64  69 6e 67 00  99 f7 e2                  │padd│ing·│···│
0000000b
```

好多了！

总的来说，要在 Pwntools 中修复这种问题，请保证你所有的字符串都有一个 `b` 前缀。这解决了歧义并使一切变得简单。

### 陷阱（Gotchas）

这里有一个关于 Python3 `bytes` 对象的“陷阱”（"gotcha"）值得一提。当迭代它们时，你会得到整数，而不是 `bytes` 对象。这是 Python3 与 Python2 的巨大不同，也是一个主要的烦恼。

```
>>> x=b'123'
>>> for i in x:
...     print(i)
...
49
50
51
```

为了解决这个问题，我们建议使用长度为 1 的切片来生成 `bytes` 对象。 

```
>>> for i in range(len(x)):
...     print(x[i:i+1])
...
b'1'
b'2'
b'3'
```

