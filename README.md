# Extended Berkeley Packet Filter (eBPF)

## **1️⃣ Introduction**
eBPF (Extended Berkeley Packet Filter) allows programs to be attached to different kernel events and execute efficiently in the kernel space.

---

## **2️⃣ Triggering eBPF Programs**
eBPF programs can be attached to various events, including:
- **kprobes** – Hooks into kernel functions.
- **uprobes** – Hooks into user-space functions.
- **Tracepoints** – Generic kernel trace events.
- **Network Packets** – Used in filtering and monitoring.
- **Linux Security Module (LSM)** – Security-related hooks.
- **Perf Events** – Performance monitoring events.

---

## **3️⃣ eBPF Helper Functions**
### **📌 `bpf_trace_printk()`**
- Writes a message to the kernel trace buffer (`/sys/kernel/debug/tracing/trace_pipe`).

### **📌 `b.trace_print()`**
- Reads messages from the kernel trace buffer and prints them.

---

## **4️⃣ Attaching eBPF Programs**
### **📌 Using `b.attach_kprobe()`**
- Attaches an eBPF program dynamically to a kernel function.
- Example:
  ```c
  b.attach_kprobe(event="sys_execve", fn_name="hello")

    This hooks the function hello() to the execve system call.

💡 Multiple eBPF programs writing to trace_pipe can make logs hard to read.
5️⃣ BPF Maps – Data Structures in eBPF

BPF Maps allow kernel and user-space programs to exchange data.
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

    Extracts the lower 32 bits, which contain the UID.

📌 Get PID of a Running Process

bpf_get_current_pid_tgid() >> 32;

    Extracts the upper 32 bits, which contain the PID.

7️⃣ Hash Tables and Performance

    Hash tables provide constant-time lookup (O(1)).
    Implemented as:
        Linked lists → O(n) traversal.
        Hash functions → O(1) retrieval.

Example:

counter_table.lookup(&key);
counter_table.update(&key, &value);

    Looks up a value in counter_table using key.
    Updates the value associated with key.

8️⃣ Perf and Ring Buffer Maps
📌 Ring Buffers

    Circular memory buffers with separate read and write pointers.
    Used for efficient data streaming between eBPF (kernel) and user-space applications.

9️⃣ Passing Data from Kernel to User-Space
📌 Using BPF_PERF_OUTPUT

BPF_PERF_OUTPUT(output);

    Used to send messages from the kernel to user-space.

🔹 Key eBPF Helper Functions
📌 bpf_get_current_comm()

Retrieves the name of the currently executing process.

bpf_get_current_comm(data.command, sizeof(data.command));

Function Signature:

int bpf_get_current_comm(char *buf, int size);

    buf → Pointer to destination buffer.
    size → Buffer size.

📌 bpf_probe_read_kernel()

Reads data from kernel memory (not local variables).

bpf_probe_read_kernel(&data.msg, sizeof(data.msg), src_pointer);

    src_pointer: Kernel memory location.
    data.msg: Destination buffer.

📌 output.perf_submit()

Sends data from eBPF to user-space.

output.perf_submit(ctx, &data, sizeof(data));

    ctx → Execution context.
    data → Struct holding event data.
    sizeof(data) → Size of struct.
