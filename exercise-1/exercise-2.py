#!/usr/bin/python
from bcc import BPF
from time import sleep

# Define the eBPF program in C syntax as a multi-line raw string
program = r"""
#include <uapi/linux/ptrace.h>

// Declare a BPF hash map (key-value store) to track execution counts per UID
BPF_HASH(counter_table);

// Common eBPF function to increment the counter for a UID
static inline void increment_counter(u64 uid) {
    u64 counter = 0;
    u64 *p;

    // Lookup the current value in the hash table using UID as the key
    p = counter_table.lookup(&uid);

    if (p != 0) {  // If key exists, retrieve its value
        counter = *p;
    }

    // Increment the counter
    counter++;

    // Update the hash table with the new count for this UID
    counter_table.update(&uid, &counter);
}

// eBPF function for execve syscall
int hello_execve(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    increment_counter(uid);
    return 0;
}

// eBPF function for openat syscall
int hello_openat(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    increment_counter(uid);
    return 0;
}

// eBPF function for write syscall
int hello_write(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    increment_counter(uid);
    return 0;
}
"""

# Load the eBPF program into the kernel
b = BPF(text=program)

# Attach the eBPF functions to their respective syscalls using kprobes
syscall_execve = b.get_syscall_fnname("execve")
syscall_openat = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")

b.attach_kprobe(event=syscall_execve, fn_name="hello_execve")
b.attach_kprobe(event=syscall_openat, fn_name="hello_openat")
b.attach_kprobe(event=syscall_write, fn_name="hello_write")

# Periodically print the execution count of the syscalls per user ID
while True:
    sleep(2)  # Wait for 2 seconds before printing again
    s = ""
    
    # Iterate through the BPF hash table and print the counter for each UID
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"  # Format the output
    
    print(s)  # Print the execution count of syscalls per UID