目录
=================

  * [管](#管Tubes)
    * [基本 IO](#基本-io)
      * [接收数据](#接收数据)
      * [发送数据](#发送数据)
      * [操作整数](#操作整数)
    * [进程和基本功能](#进程和基本功能)
    * [交互式会话](#交互式会话)
    * [网络](#网络)
    * [Secure Shell（SSH）](#secure-shellssh)
    * [串口 ](#串口 )

# 管（Tubes）

管（Tube）包装了大多数你可能需要执行的 I/O 类型，包括： 

-   本地进程 
-   远程 TCP 或 UDP 连接 
-   通过 SSH 在远程服务器上运行的进程 
-   串口输入/输出 

本介绍提供了部分功能的示例，但更复杂的组合也是可能的。关于如何执行正则表达式匹配以及将管（tube）连接在一起的更多信息，请参阅 [完整文档 ](https://pwntools.readthedocs.org/en/latest/tubes.html)。

## 基本 IO

你可能希望从 IO 中获得的基本功能是： 

### 接收数据

- `recv(n)` - 接收任意数量的可用字节
- `recvline()` - 接收数据直到遇到换行符
- `recvuntil(delim)` - 接收数据直到找到分隔符
- `recvregex(pattern)` - 接收数据直到满足正则表达式模式
- `recvrepeat(timeout)` - 继续接收数据，直到发生超时
- `clean()` - 丢弃所有缓冲数据

### 发送数据

- `send(data)` - 发送数据
- `sendline(line)` - 发送数据加上换行符

### 操作整数

- `pack(int)` - 发送一个字长的压缩整数 
- `unpack()` - 接收并解包一个字长的整数 

## 进程和基本功能

要创建一个与进程对话的管（tube），你只需创建一个 `process` 对象并告诉它目标二进制文件的名称。 

```py
from pwn import *

io = process('sh')
io.sendline('echo Hello, world')
io.recvline()
# 'Hello, world\n'
```

使用命令行参数或设置环境变量。请参阅 [完整文档 ](https://pwntools.readthedocs.org/en/latest/tubes/processes.html)。

```py
from pwn import *

io = process(['sh', '-c', 'echo $MYENV'], env={'MYENV': 'MYVAL'})
io.recvline()
# 'MYVAL\n'
```

读取二进制数据。 你可以用 `recv` 接收多个字节 ，或使用 `recvn` 指定接受的字节数目。

```py
from pwn import *

io = process(['sh', '-c', 'echo A; sleep 1; echo B; sleep 1; echo C; sleep 1; echo DDD'])

io.recv()
# 'A\n'

io.recvn(4)
# 'B\nC\n'

hex(io.unpack())
# 0xa444444
```

## 交互式会话

获取shell后转到手动交互模式。

```py
from pwn import *

# Let's pretend we're uber 1337 and landed a shell.
io = process('sh')

# <exploit goes here>

io.interactive()
```


## 网络

创建网络连接也很容易，并且具有完全相同的接口。`remote`对象用于连接到其他地方，而 `listen`对象用于等待连接。

```py
from pwn import *

io = remote('google.com', 80)
io.send('GET /\r\n\r\n')
io.recvline()
# 'HTTP/1.0 200 OK\r\n'
```

指定协议信息，也非常简单。 

```py
from pwn import *

dns  = remote('8.8.8.8', 53, typ='udp')
tcp6 = remote('google.com', 80, fam='ipv6')
```

监听连接并不复杂。请注意，这只会监听一个连接，然后停止。 

```py
from pwn import *

client = listen(8080).wait_for_connection()
```

## Secure Shell（SSH）

SSH 连接同样简单。将下面的代码与上面的进程中的代码进行比较。 

还可以使用 SSH 做更复杂的事情，例如端口转发和文件上传/下载。请参阅 [SSH 教程 ](https://github.com/Gallopsled/pwntools-tutorial/blob/master/ssh.md)。 

```py
from pwn import *

session = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0')

io = session.process('sh', env={"PS1":""})
io.sendline('echo Hello, world!')
io.recvline()
# 'Hello, world!\n'
```

## 串口

如果您需要完成一些本地黑客攻击，还有一个串行管（tube）。请参阅 [完整的在线文档 ](https://pwntools.readthedocs.org/en/latest/tubes/serial.html)。 

```py
from pwn import *

io = serialtube('/dev/ttyUSB0', baudrate=115200)
```

[docs]: https://pwntools.readthedocs.org/en/latest/tubes.html
[process]: https://pwntools.readthedocs.org/en/latest/tubes/processes.html
[ssh]: ssh.md
[remote]: https://pwntools.readthedocs.org/en/latest/tubes/sock.html
[serial]: https://pwntools.readthedocs.org/en/latest/tubes/serial.html



