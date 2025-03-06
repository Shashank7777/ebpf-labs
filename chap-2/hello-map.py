#!/usr/bin/python  # Specifies the interpreter to be Python

# Import BPF class from the BCC module
from bcc import BPF  
from time import sleep  # Import sleep function for periodic output

# Define the eBPF program in C syntax as a multi-line raw string
program = r"""
// Declare a BPF hash map (key-value store) to track execution counts per UID
BPF_HASH(counter_table);

int hello(void *ctx) {  // eBPF function that runs when execve syscall is executed
        u64 uid;
        u64 counter = 0;  // Default counter value
        u64 *p;

        // Get the UID of the current running process
        uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

        // Lookup the current value in the hash table using UID as the key
        p = counter_table.lookup(&uid);

        if (p != 0) {  // If key exists, retrieve its value
                counter = *p;
        }

        // Increment the counter
        counter++;

        // Update the hash table with the new count for this UID
        counter_table.update(&uid, &counter);

        return 0;  // Return 0 indicating successful execution
}
"""

# Load the eBPF program into the kernel
b = BPF(text=program)

# Get the correct system call name for "execve"
syscall = b.get_syscall_fnname("execve")

# Attach the eBPF function "hello" to the "execve" syscall using a kprobe
b.attach_kprobe(event=syscall, fn_name="hello")

# Periodically print the execution count of the execve syscall per user ID
while True:
        sleep(2)  # Wait for 2 seconds before printing again
        s = ""
        
        # Iterate through the BPF hash table and print the counter for each UID
        for k, v in b["counter_table"].items():
                s += f"ID {k.value}: {v.value}\t"  # Format the output
        
        print(s)  # Print the execution count of execve per UID
