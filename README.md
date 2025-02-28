# ebpf-labs
Extended Berkeley Packet Filter (eBPF)

# Extended Berkeley Packet Filter (eBPF)

## **1️⃣ Introduction to eBPF**
Extended Berkeley Packet Filter (eBPF) allows programs to be executed **inside the Linux kernel** without modifying kernel source code.  
eBPF is widely used for **tracing, networking, security, and performance monitoring**.

---

## **2️⃣ Triggering eBPF Programs**
eBPF programs can be attached to different events in the Linux kernel, such as:
- **kprobes** – Hooks into kernel functions.
- **uprobes** – Hooks into user-space functions.
- **Tracepoints** – Generic kernel trace events.
- **Network Packets** – Used in filtering and monitoring.
- **Linux Security Module (LSM)** – Security-related hooks.
- **Perf Events** – Performance monitoring events.

---

## **3️⃣ Using eBPF Helper Functions**
### **📌 `bpf_trace_printk()`**
- Used for logging messages to the kernel trace buffer (`/sys/kernel/debug/tracing/trace_pipe`).
- Example:
  ```c
  bpf_trace_printk("Hello, eBPF!\n");

📌 b.trace_print()

    Reads messages from the kernel trace buffer and prints them.

4️⃣ Attaching eBPF Programs
📌 Using b.attach_kprobe()

Attaches an eBPF program dynamically to a kernel function.

b.attach_kprobe(event="sys_execve", fn_name="hello")

    Hooks hello() to the execve system call.
    Runs every time a process executes a new program.

💡 If multiple eBPF programs are running, they will write output to the same trace_pipe, making it difficult to read.
5️⃣ BPF Maps – Cross-Communication Between Kernel & User-Space

BPF Maps are key-value data structures that allow eBPF programs to store and share data with user-space applications.
📌 BPF_HASH(counter_table)

BPF_HASH(counter_table);

    Creates a hash table named counter_table.
    Default declaration:

    BPF_HASH(counter_table, u64, u64, 10240);

        Key Type: u64
        Value Type: u64
        Max Elements: 10240

6️⃣ Extracting Process Information
📌 Get UID of a Running Process

bpf_get_current_uid_gid() & 0xFFFFFFFF;

    Extracts the lower 32 bits containing the UID.

📌 Get PID of a Running Process

bpf_get_current_pid_tgid() >> 32;

    Extracts the upper 32 bits containing the PID.

7️⃣ Understanding Hash Tables in eBPF

    Hash tables provide constant-time lookup (O(1)).
    Implemented as:
        Linked lists → O(n) traversal.
        Hash functions → O(1) retrieval.

Example:

counter_table.lookup(&key);
counter_table.update(&key, &value);

    Looks up a value in the counter_table using key.
    Updates the value associated with key.

8️⃣ Perf and Ring Buffer Maps
📌 Ring Buffers

    Circular memory buffers used for efficient data streaming between eBPF (kernel) and user-space.
    Uses separate read and write pointers.

9️⃣ Passing Data from Kernel to User-Space
📌 Using BPF_PERF_OUTPUT

BPF_PERF_OUTPUT(output);

    Macro that enables sending messages from kernel to user-space.

🔹 Key eBPF Helper Functions
📌 bpf_get_current_comm()

Retrieves the name of the currently executing process.

bpf_get_current_comm(data.command, sizeof(data.command));

    Stores the process name in data.command.

Function Signature:

int bpf_get_current_comm(char *buf, int size);

    buf → Pointer to destination buffer.
    size → Buffer size.

📌 bpf_probe_read_kernel()

Used for reading data from kernel memory.

bpf_probe_read_kernel(&data.msg, sizeof(data.msg), src_pointer);

    src_pointer: Kernel memory location.
    data.msg: Destination buffer.

🚨 Cannot be used for stack variables! Use __builtin_memcpy() instead.
📌 output.perf_submit()

Sends data from eBPF to user-space.

output.perf_submit(ctx, &data, sizeof(data));

    ctx → Function execution context.
    data → Struct holding event data.
    sizeof(data) → Size of struct
