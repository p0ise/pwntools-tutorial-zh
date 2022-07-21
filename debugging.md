目录
=================

  * [先决条件](#先决条件)
  * [在 GDB 下启动进程 ](#在-GDB-下启动进程 )
  * [附加到正在运行的进程](#附加到正在运行的进程)
	  * [本地进程](#本地进程)
	* [分支服务器 ](#分支服务器)
  * [调试其他架构](#调试其他架构)
  * [故障排除](#故障排除)
	  * [幕后](#幕后)
	* [指定终端窗口](#指定终端窗口)
	* [环境变量](#环境变量)
	* [无法附加到进程](#无法附加到进程)
	* [argv0 和 argc==0](#argv0-和-argc==0)

Pwntools 对在漏洞利用工作流中使用调试器提供了丰富的支持，并且在开发漏洞利用出现问题时，调试器非常有用。 

除了此处用于调试的资源之外，你可能还想用以下项目之一来增强你的 GDB 体验： 

* [Pwndbg](https://pwndbg.re)
* [GDB Enhanced Features (GEF)](https://github.com/hugsy/gef)

# 先决条件

你应该在你的机器上同时安装了 `gdb` 和 `gdbserver` 。可以通过 `which gdb` 或者 `which gdbserver` 的方式检查。

如果你发现你没有安装它们，可以很容易地从大多数包管理器安装。 

```sh
$ sudo apt-get install gdb gdbserver
```

# 在 GDB 下启动进程

在 GDB 下启动一个进程，同时仍然能从 pwntools 与该进程交互是一个棘手的过程，但幸运的是，这一切都已解决，并且过程非常无缝。

要从第一条指令在 GDB 下启动进程，只需使用  [gdb.debug](https://docs.pwntools.com/en/stable/gdb.html#pwnlib.gdb.debug)。 

```py
>>> io = gdb.debug("/bin/bash", gdbscript='continue')
>>> io.sendline('echo hello')
>>> io.recvline()
# b'hello\n'
>>> io.interactive()
```

这应该会在新窗口中自动启动调试器，以便进行交互。如果没有，或者你看到关于 `context.terminal` 的错误，请查看 [指定终端窗口](https://github.com/Gallopsled/pwntools-tutorial/blob/master/debugging.md#specifying-a-terminal-window) 部分。 

在这个例子中，我们传入 `gdbscript='continue'`来让调试器恢复执行，但你也可以传入任何有效的 GDB 脚本命令，它们将在被调试进程启动时执行。 

# 附加到正在运行的进程

有时你不想在调试器下启动目标，但想在开发 exp 过程的某个阶段对其进行附加调试处理。 
这也由 Pwntools 无缝处理。 

## 本地进程

通常，你会创建一个 `process()`管，以便与目标可执行文件交互。你可以简单地将其传递给 `gdb.attach()` ，它会神奇地在调试器下使用目标二进制文件打开一个新的终端窗口。 

```py
>>> io = process('/bin/sh')
>>> gdb.attach(io, gdbscript='continue')
```

应该会出现一个新窗口，同时你可以像通常那样在 Pwntools 中继续与该进程进行交互。 

## 分支服务器

有时候你会想像在分支服务器上一样调试二进制文件，并且同时调试你连接到的进程（而不是服务器本身）。这很容易完成，只要让服务器在当前机器运行即可。

让我们伪造一个带有 socat 的服务器！

```py
>>> socat = process(['socat', 'TCP-LISTEN:4141,reuseaddr,fork', 'EXEC:/bin/bash -i'])
```

让我们像往常一样使用 `remote` 连接到远程进程。


```py
>>> io = remote('localhost', 4141)
[x] Opening connection to localhost on port 4141
[x] Opening connection to localhost on port 4141: Trying 127.0.0.1
[+] Opening connection to localhost on port 4141: Done
>>> io.sendline('echo hello')
>>> io.recvline()
b'hello\n'
>>> io.lport, io.rport
```

它成功了！为了调试我们 `remote` 对象的特定 `bash` 进程，只需要将它传递给 `gdb.attach()`。Pwntools 会查找远端连接的 PID 并尝试自动连接。

```py
>>> gdb.attach(io)
```

调试器应该会自动出现，然后你就可以和进程交互了。

<!-- TODO: This is currently broken, see https://github.com/Gallopsled/pwntools/issues/1589 -->

# 调试其他架构

在基于 Intel 的系统上调试其他架构（如 ARM 或 PowerPC）和在 pwntools 上运行他们一样容易。

```py
>>> context.arch = 'arm'
>>> elf = ELF.from_assembly(shellcraft.echo("Hello, world!\n") + shellcraft.exit())
>>> process(elf.path).recvall()
b'Hello, world!\n'
```

只需要用 `gdb.debug(...)` 替代 `process(...)`。

```py
>>> gdb.debug(elf.path).recvall()
b'Hello, world!\n'
```

## 提示和限制

要想调试运行其他架构的进程，**必须**使用 `gdb.debug` 来启动他们，否则，由于 QEMU 的工作方式，是不可能附加到一个正在运行的进程中的。

应当注意 QEMU 有一个非常受限的 GDB 存根（stub），它用于告知 GDB 各种库在哪里，因此调试可能非常困难，并且有一些命令无法使用。

Pwntools recommends Pwndbg to handle this situation, since it has code specifically to handle debugging under a QEMU stub.

Pwntools 推荐使用 Pwndbg 来处理这种情况，因为它有专门的代码处理 QEMU 存根下的调试。 

<!-- TODO: There is no tutorial for interacting with cross-arch binaries -->

# 故障排除

## 幕后

有时怎样都行不通，你可能想通过调试器设置看看 Pwntools 内部发生了什么。 

您可以在全局设置日志记录上下文（通过例如 `context.log_level='debug'`）或仅为 GDB 会话设置。 

您应该可以看到在幕后为您处理的所有事情。例如： 

```py
>>> io = gdb.debug('/bin/sh', log_level='debug')
[x] Starting local process '/home/user/bin/gdbserver' argv=[b'/home/user/bin/gdbserver', b'--multi', b'--no-disable-randomization', b'localhost:0', b'/bin/sh']
[+] Starting local process '/home/user/bin/gdbserver' argv=[b'/home/user/bin/gdbserver', b'--multi', b'--no-disable-randomization', b'localhost:0', b'/bin/sh'] : pid 34282
[DEBUG] Received 0x25 bytes:
    b'Process /bin/sh created; pid = 34286\n'
[DEBUG] Received 0x18 bytes:
    b'Listening on port 45145\n'
[DEBUG] Wrote gdb script to '/tmp/user/pwnxcd1zbyx.gdb'
    target remote 127.0.0.1:45145
[*] running in new terminal: /usr/bin/gdb -q  "/bin/sh" -x /tmp/user/pwnxcd1zbyx.gdb
[DEBUG] Launching a new terminal: ['/usr/local/bin/tmux', 'splitw', '/usr/bin/gdb -q  "/bin/sh" -x /tmp/user/pwnxcd1zbyx.gdb']
[DEBUG] Received 0x25 bytes:
    b'Remote debugging from host 127.0.0.1\n'
```

## 指定终端窗口

Pwntools 尝试基于您当前使用的窗口系统在新窗口中启动调试器。 

默认情况下，它会自动检测：

* tmux 或 screen
* 基于 X11 的终端，例如 GNOME 终端 

如果您没有使用受支持的终端环境，或者它没有按你想要的方式（例如水平与垂直分割）运作，你可以通过设置 `context.terminal` 环境变量添加支持。 

比如下面会使用 TMUX 来横向分割，而不是默认的。 

```py
>>> context.terminal = ['tmux', 'splitw', '-h']
```

也许您是 GNOME 终端用户并且默认设置不起作用？ 

```py
>>> context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
```

你可以指定任何你喜欢的终端，甚至可以把设置放在 `~/.pwn.conf` 里面，这样它就可以作用于你所有的脚本！ 

```
[context]
terminal=['x-terminal-emulator', '-e']
```

## 环境变量

Pwntools allows you to specify any environment variables you like via `process()`, and the same is true for `gdb.debug()`.

Pwntools 允许您通过 `process()` 指定您喜欢的任何环境变量，这同样适用于 `gdb.debug()`。

```py
>>> io = gdb.debug(['bash', '-c', 'echo $HELLO'], env={'HELLO': 'WORLD'})
>>> io.recvline()
b'WORLD\n'
```

### `CWD` and `   `

不幸的是，当使用 `gdb.debug()` 时, 该进程在添加了自己的环境变量的 `gdbserver` 下启动。 这可能会引入副作用，必须非常小心地控制环境。 

```py
>>> io = gdb.debug(['env'], env={'FOO':'BAR'}, gdbscript='continue')
>>> print(io.recvallS())
   =/home/user/bin/gdbserver
FOO=BAR

Child exited with status 0
GDBserver exiting
```

这仅在您通过 `gdb.debug()` 在调试器下启动进程时发生。如果您先启动您的进程， *然后*使用 `gdb.attach()` 附加，就可以避免这个问题。 

### 环境变量排序

一些漏洞利用可能需要特定顺序的一些环境变量。Python2 字典是无序的，这可能会加剧这个问题。 

为了使您的环境变量按特定顺序排列，我们建议使用 Python3（字典序基于插入的顺序），或使用 `collections.OrderedDict`。

## 无法附加到进程

现代 Linux 系统有一个设置叫做 `ptrace_scope` 用于防止那些不是子进程的进程被调试。  Pwntools 可以解决这个问题，它自己来启动进程，但如果您不得不在 Pwntools 之外启动一个进程并尝试通过 pid 附加到它（例如 `gdb.attach(1234)`）, 可能会无法连接。 

您可以通过禁用这项安全设置并重新启动计算机来解决此问题： 

```sh
sudo tee /etc/sysctl.d/10-ptrace.conf <<EOF
kernel.yama.ptrace_scope = 0
EOF
```

## argv0 和 argc==0

一些挑战要求它们在`argv[0]`特定的值下启动，甚至是 NULL（即 `argc==0`）。

此时你无法通过此配置启动进程 `gdb.debug()`，但你可以使用 `gdb.attach()`。这是因为 gdbserver 下二进制文件启动的限制。 