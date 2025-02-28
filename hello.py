#!/usr/bin/python
# This line specifies that the script should be executed using Python.

from bcc import BPF  
# Importing the BPF class from the BCC (BPF Compiler Collection) module.
# This allows us to compile and run eBPF programs from Python.

# Define the eBPF program as a raw string (r""") to avoid escape character issues.
program = r"""
int hello(void *ctx) { 
    // Define an eBPF function named "hello" that takes a context pointer (ctx) as input.
    bpf_trace_printk("Hello World!"); 
    // This helper function prints "Hello World!" to the BPF tracing buffer (/sys/kernel/debug/tracing/trace_pipe).
    return 0;  
    // Return 0 to indicate successful execution.
}
"""

# Create an instance of BPF, compiling and loading the eBPF program into the kernel.
b = BPF(text=program)

# Resolve the correct system call name for "execve" (it may differ across architectures).
syscall = b.get_syscall_fnname("execve")

# Attach the eBPF function "hello" to the "execve" system call using a kernel probe (kprobe).
b.attach_kprobe(event=syscall, fn_name="hello")

# Start reading and printing the tracing output in real-time from trace_pipe.
b.trace_print()
