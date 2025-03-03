#!/usr/bin/python3

# Import the BPF class from the BCC module
from bcc import BPF  
from time import sleep  # Import sleep function for periodic polling of the perf buffer

# Define the eBPF program as a multi-line raw string
program = r"""
// Declare a perf buffer named "output" for sending data from the eBPF program to user-space
BPF_PERF_OUTPUT(output);

// Define a struct that will hold the process execution data
struct data_t {
    int pid;          // Process ID of the executed process
    int uid;          // User ID of the process owner
    char command[16]; // Command name (process name)
    char message[12]; // Fixed: Removed stray single quote
};

// The eBPF function that will run when an `execve` syscall is executed
int hello(void *ctx) {
    struct data_t data = {};  // Initialize the struct

    // Local stack variable to store a message
    char message[12]; // Stack-allocated buffer for the message



    // Get the PID of the process that executed `execve`
    data.pid = bpf_get_current_pid_tgid() >> 32;

    // Get the UID of the user who owns the process
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    //if (data.pid % 2 == 0) {
    //    bpf_probe_read_kernel(&data.message, sizeof(data.message), "EVEN PID");
    //} else {
    //    bpf_probe_read_kernel(&data.message, sizeof(data.message), "ODD PID");
    //}

    // Determine if the PID is odd or even and set the message accordingly
    if (data.pid % 2 == 0) {
        __builtin_memcpy(message, "EVEN PID", sizeof("EVEN PID"));
    } else {
        __builtin_memcpy(message, "ODD PID", sizeof("ODD PID"));
    }  


    // Get the command name of the process
    bpf_get_current_comm(&data.command, sizeof(data.command));

    // Corrected: Use __builtin_memcpy() to safely copy stack memory
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    // Submit the event to user-space via the perf buffer
    output.perf_submit(ctx, &data, sizeof(data));

    return 0;  // Return 0 indicating successful execution
}
"""

# Load the eBPF program into the kernel
b = BPF(text=program)

# Get the system call name for "execve" (varies by architecture)
syscall = b.get_syscall_fnname("execve")

# Attach the eBPF function "hello" to the "execve" syscall using a kprobe
b.attach_kprobe(event=syscall, fn_name="hello")

# Define a callback function to handle received events from the perf buffer
def print_event(cpu, data, size):
    """
    Callback function to process received data from the eBPF program.
    - Extracts the data struct from the perf buffer.
    - Decodes and prints the process execution details.
    """
    data = b["output"].event(data)  # Retrieve the struct data from the perf buffer

    # Print the execution event detail
    print(f"PID: {data.pid}, UID: {data.uid}, Command: {data.command.decode()}, Message: {data.message.decode()}")

# Open the perf buffer and set the callback function to process received events
b["output"].open_perf_buffer(print_event)

# Continuously poll for new events and process them in real-time
while True:
    b.perf_buffer_poll()
