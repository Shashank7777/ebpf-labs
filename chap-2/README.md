Chapter Notes: eBPF "Hello World" Example

This chapter introduces a simple "Hello World" example using eBPF to help you understand how eBPF programs run in the kernel. The example uses the BCC Python framework, which is beginner-friendly but not necessarily recommended for production applications. The chapter also covers key concepts like kprobes, BPF maps, helper functions, and tail calls.
Key Takeaways

    BCC Python Framework:

        BCC (BPF Compiler Collection) provides an easy way to write and run eBPF programs using Python.

        It abstracts away many complexities, such as compiling and loading eBPF programs into the kernel.

        Example: A simple "Hello World" eBPF program that prints a message whenever the execve() syscall is triggered.

    eBPF Program Structure:

        Kernel Space: The eBPF program runs in the kernel and is triggered by specific events (e.g., syscalls).

        User Space: The Python script loads the eBPF program, attaches it to an event, and reads the output.

    Hello World Example:

        The eBPF program uses bpf_trace_printk() to print "Hello World!" to the kernel trace pipe.

        The Python script attaches the eBPF program to the execve() syscall using a kprobe.

        Output is read from /sys/kernel/debug/tracing/trace_pipe.

    BPF Maps:

        Maps are data structures that allow communication between eBPF programs and user space.

        Types of maps: Hash tables, arrays, perf buffers, ring buffers, etc.

        Example: A hash table map is used to count how many times each user executes a program.

    Helper Functions:

        eBPF programs can call helper functions to interact with the system.

        Examples:

            bpf_trace_printk(): Prints a message to the kernel trace pipe.

            bpf_get_current_uid_gid(): Retrieves the user ID of the process triggering the event.

            bpf_get_current_pid_tgid(): Retrieves the process ID.

            bpf_get_current_comm(): Retrieves the name of the executable.

    Perf and Ring Buffers:

        Perf buffers: Used to pass structured data from the kernel to user space.

        Ring buffers: A newer and more efficient alternative to perf buffers (introduced in kernel 5.8).

        Example: A perf buffer is used to pass process ID, user ID, and command name to user space.

    Function Calls and Tail Calls:

        Function Calls: Early eBPF programs required functions to be inlined (__always_inline). Modern eBPF supports BPF-to-BPF function calls (kernel 4.16+).

        Tail Calls: Allow one eBPF program to call another, replacing the current execution context. Useful for breaking down complex logic into smaller programs.

        Example: A tail call is used to handle specific syscalls (e.g., execve() and timer-related syscalls).

    Privileges:

        eBPF programs require special privileges to run.

        Root user or capabilities like CAP_BPF, CAP_PERFMON, and CAP_NET_ADMIN are needed depending on the type of eBPF program.