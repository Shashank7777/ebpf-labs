# Extended Berkeley Packet Filter (eBPF)

## Introduction

eBPF (Extended Berkeley Packet Filter) allows programs to be attached to different kernel events and execute efficiently in the kernel space. eBPF is widely used for tracing, networking, security, and performance monitoring.

## Triggering eBPF Programs

eBPF programs can be attached to various events in the Linux kernel, including:

- kprobes - Hooks into kernel functions
- uprobes - Hooks into user-space functions
- Tracepoints - Generic kernel trace events
- Network Packets - Used in filtering and monitoring
- Linux Security Module (LSM) - Security-related hooks
- Perf Events - Performance monitoring events

## eBPF Helper Functions

### bpf_trace_printk()
Writes a message to the kernel trace buffer located at `/sys/kernel/debug/tracing/trace_pipe`.

### b.trace_print()
Reads messages from the kernel trace buffer and prints them.

## Attaching eBPF Programs

### Using b.attach_kprobe()
Attaches an eBPF program dynamically to a kernel function.

Example:
```c
b.attach_kprobe(event="sys_execve", fn_name="hello")

This hooks the function hello() to the execve system call. If multiple eBPF programs write to trace_pipe, logs can become difficult to read.
BPF Maps - Data Structures in eBPF

BPF Maps allow kernel and user-space programs to exchange data.

Example:

BPF_HASH(counter_table);

Creates a hash table named counter_table.

Default declaration:

BPF_HASH(counter_table, u64, u64, 10240);

    Key type: u64
    Value type: u64
    Maximum elements: 10240

Extracting Process Information
Get UID of a Running Process

bpf_get_current_uid_gid() & 0xFFFFFFFF;

Extracts the lower 32 bits, which contain the UID.
Get PID of a Running Process

bpf_get_current_pid_tgid() >> 32;

Extracts the upper 32 bits, which contain the PID.
Hash Tables and Performance

Hash tables provide constant-time lookup.
They are implemented as:

    Linked lists which have linear time complexity
    Hash functions which allow constant time lookup

Example:

counter_table.lookup(&key);
counter_table.update(&key, &value);

Looks up a value in counter_table using key and updates the value associated with key.
Perf and Ring Buffer Maps
Ring Buffers

Circular memory buffers with separate read and write pointers.
Used for efficient data streaming between eBPF running in the kernel and user-space applications.
Passing Data from Kernel to User-Space
Using BPF_PERF_OUTPUT

BPF_PERF_OUTPUT(output);

Used to send messages from the kernel to user-space.
Key eBPF Helper Functions
bpf_get_current_comm()

Retrieves the name of the currently executing process.

Example:

bpf_get_current_comm(data.command, sizeof(data.command));

Function Signature:

int bpf_get_current_comm(char *buf, int size);

    buf is the pointer to the destination buffer.
    size is the buffer size.

bpf_probe_read_kernel()

Reads data from kernel memory.

Example:

bpf_probe_read_kernel(&data.msg, sizeof(data.msg), src_pointer);

    src_pointer is the kernel memory location.
    data.msg is the destination buffer.

output.perf_submit()

Sends data from eBPF to user-space.

Example:

output.perf_submit(ctx, &data, sizeof(data));

    ctx is the execution context.
    data is the struct holding event data.
    sizeof(data) is the size of the struct.
