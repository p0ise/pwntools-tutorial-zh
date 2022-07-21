目录
=================

  * [安装 Pwntools](#安装-Pwntools)
    * [验证安装](#验证安装)
    * [外部架构](#外部架构)

# 安装 Pwntools

这个过程尽可能简单。Ubuntu 18.04 和 20.04 是唯一的“官方支持”平台，因为它们是我们进行自动化测试的唯一平台。 

```sh
$ apt-get update
$ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
$ python3 -m pip install --upgrade pip
$ python3 -m pip install --upgrade pwntools
```

## 验证安装

如果以下命令成功，一切都应该是正常的（A-OK）： 

```sh
$ python -c 'from pwn import *'
```

## 外部架构

如果你想为外部架构汇编或反汇编代码，你需要一个合适的 `binutils`安装。对于 Ubuntu 和 Mac OS X 用户， [安装说明 ](https://pwntools.readthedocs.org/en/latest/install/binutils.html)可在 docs.pwntools.com 上获得。 

```sh
$ apt-get install binutils-*
```

[binutils]: https://pwntools.readthedocs.org/en/latest/install/binutils.html
