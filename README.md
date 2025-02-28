###eBPF Examples and Explanation

This repository contains three Python scripts that demonstrate the use of eBPF (Extended Berkeley Packet Filter) for tracing system calls and collecting data in real-time. Below is a detailed explanation of each script and the fundamental concepts behind them.
###1. hello.py
###Description:

This script attaches an eBPF program to the execve system call and prints "Hello World!" to the kernel trace buffer whenever execve is executed.
###Key Concepts:

    eBPF Program: A small program written in C that runs in the kernel. In this case, it prints a message using bpf_trace_printk().

    Kprobes: Kernel probes that allow attaching eBPF programs to kernel functions, such as system calls.

    Trace Buffer: The kernel's tracing buffer (/sys/kernel/debug/tracing/trace_pipe) where messages from bpf_trace_printk() are stored.

###Code Explanation:

    eBPF Program:

        Defines a function hello() that prints "Hello World!" using bpf_trace_printk().

    Python Script:

        Loads the eBPF program into the kernel using BPF(text=program).

        Attaches the hello() function to the execve system call using b.attach_kprobe().

        Reads and prints messages from the trace buffer using b.trace_print().

###2. hello-map.py
###Description:

This script extends the functionality of hello.py by using a BPF hash map to count how many times the execve system call is executed per user ID (UID).
###Key Concepts:

    BPF Maps: Data structures that allow sharing data between the eBPF program and user-space. In this case, a hash map (BPF_HASH) is used to store execution counts per UID.

    UID Tracking: The eBPF program retrieves the UID of the process executing execve using bpf_get_current_uid_gid().

    Periodic Output: The Python script periodically prints the contents of the BPF hash map.

###Code Explanation:

    eBPF Program:

        Declares a hash map counter_table to store execution counts per UID.

        Retrieves the UID of the current process and increments its count in the hash map.

    Python Script:

        Loads the eBPF program and attaches it to the execve system call.

        Periodically iterates through the hash map and prints the execution counts for each UID.

###3. hello-buffer.py
###Description:

This script demonstrates how to use a perf buffer to send structured data (e.g., process ID, UID, command name) from the eBPF program to user-space.
###Key Concepts:

    Perf Buffer: A high-performance ring buffer that allows efficient data transfer between the kernel and user-space.

    Structured Data: The eBPF program defines a data_t struct to organize the data (PID, UID, command name, and a message).

    Callback Function: A Python function (print_event) processes and prints the data received from the perf buffer.

###Code Explanation:

    eBPF Program:

        Declares a perf buffer output for sending data to user-space.

        Defines a data_t struct to hold process execution details.

        Retrieves the PID, UID, and command name of the process executing execve.

        Submits the data to the perf buffer using output.perf_submit().

    Python Script:

        Loads the eBPF program and attaches it to the execve system call.

        Defines a callback function print_event to process and print data received from the perf buffer.

        Continuously polls the perf buffer for new events using b.perf_buffer_poll()
