# Import the BPF class from the BCC module
from bcc import BPF  
from time import sleep  # Import sleep function for periodic polling of the perf buffer
import ctypes as ct
# Define the eBPF program as a multi-line raw string
program = r"""
// Define a structure to hold custom messages
struct user_msg_t {
	char message[12];
};

// Create a hash map named 'config' that maps UIDs (u32) to custom messages
BPF_HASH(config, u32, struct user_msg_t);

// Create a perf output buffer named 'output' to send data to user space
BPF_PERF_OUTPUT(output);

// Define the structure for data to be sent to user space
struct data_t {
	int pid;           // Process ID
	int uid;           // User ID
	char command[16];  // Command name
	char message[12];  // Custom message
};

// Entry point function that will be attached to a kernel probe
int hello(void *ctx) {
	// Initialize an empty data structure
	struct data_t data = {};
	
	// Pointer to hold a custom message from the config map
	struct user_msg_t *p;
	
	// Default message if no custom message is found
	char message[12] = "Hello World";
	
	// Get the process ID (PID) of the current process
	data.pid = bpf_get_current_pid_tgid() >> 32;
	
	// Get the user ID (UID) of the current process
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	
	// Get the command name of the current process
	bpf_get_current_comm(&data.command, sizeof(data.command));
	
	// Look up if there's a custom message for this UID in the config map
	p = config.lookup(&data.uid);
	
	// If a custom message exists for this UID, use it
	if (p !=0 ) {
		bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
	} else {
		// Otherwise, use the default "Hello World" message
		bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
	}
	
	// Send the data to user space via the perf output buffer
	output.perf_submit(ctx, &data, sizeof(data));
	
	// Return 0 to indicate success
	return 0;
}
"""

# Create a BPF object with our program
b = BPF(text=program)

# Get the kernel function name for the 'execve' system call
syscall = b.get_syscall_fnname("execve")

# Attach our 'hello' function to be triggered whenever the 'execve' syscall occurs
b.attach_kprobe(event=syscall, fn_name="hello")

b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
b["config"][ct.c_int(1000)] = ct.create_string_buffer(b"Hi user X!")

# Callback function that processes events received from the kernel
def print_event(cpu, data, size):
	# Convert the raw data to our data_t structure
	data = b["output"].event(data)
	
	# Print the received information in a formatted way
	# Note: decode() converts the byte strings to Python strings
	print(f"PID: {data.pid}, UID: {data.uid}, Command: {data.command.decode()}, Message: {data.message.decode()}")

# Open the perf buffer and set the callback function to process received events
b["output"].open_perf_buffer(print_event)

# Continuously poll for new events and process them in real-time
while True:
    b.perf_buffer_poll()