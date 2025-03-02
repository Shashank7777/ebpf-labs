#!/usr/bin/python3  
# Import the BPF module from BCC
from bcc import BPF
import ctypes as ct  # Import ctypes for working with C data types

# Define the eBPF program as a multi-line raw string
program = r"""
// Define a BPF program array map to store eBPF program references
BPF_PROG_ARRAY(syscall, 300);  // Maximum of 500 possible syscall handlers

// Main eBPF function that intercepts system calls
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];  // Extract the syscall opcode from arguments

    syscall.call(ctx, opcode);  // Perform a tail call to the corresponding syscall handler

    // If no tail call happens, log the syscall opcode
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

// Handler for execve (system call number 59)
int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");  // Log when execve() is called
    return 0;
}

// Handler for timer-related syscalls
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];  // Get the syscall operation type

    // Check which timer-related syscall was triggered
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");  // Logs when a timer is created
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");  // Logs when a timer is deleted
            break;
        default:
            bpf_trace_printk("Some other timer operation");  // Generic message for other timer syscalls
            break;
    }
    return 0;
}

// Default handler that does nothing (used to ignore unwanted syscalls)
int ignore_opcode(void *ctx) {
    return 0;
}
"""

# Load the eBPF program into the kernel
b = BPF(text=program)

# Attach the `hello` function to the `sys_enter` raw tracepoint
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# Load individual eBPF functions and retrieve their file descriptors
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)  # Default ignore function
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)  # Handler for execve syscall
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)  # Handler for timer syscalls

# Get a reference to the BPF program array map (BPF_PROG_ARRAY)
prog_array = b.get_table("syscall")

# Initialize all syscalls to point to the ignore function
for i in range(len(prog_array)):
    prog_array[ct.c_int(i)] = ct.c_int(ignore_fn.fd)

# Enable specific syscalls that we want to monitor:
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)  # execve (process execution)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)  # timer_create
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)  # timer_settime
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)  # timer_gettime
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)  # timer_getoverrun
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)  # timer_delete

# Print the output of the eBPF program in real-time
b.trace_print()

