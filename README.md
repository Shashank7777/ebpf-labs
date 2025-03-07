
### Learning eBPF Repository
This repository consists of every program and exercise from the book "Learning eBPF" with some modifications as well.
The programs in this collection follow the content of the book while implementing various eBPF concepts and techniques. In some cases, I've modified the original examples to explore alternative approaches or to add additional functionality.

### Contents
- Code examples organized by chapter
- Exercise solutions
- Modified versions with improvements and extensions
- Additional notes and explanations

### About eBPF
eBPF (extended Berkeley Packet Filter) is a revolutionary technology that allows running sandboxed programs within the Linux kernel without changing kernel source code or loading kernel modules. It makes the kernel programmable while maintaining safety and performance.

### Key Features of eBPF
- In-kernel Virtual Machine: eBPF programs run in a virtual machine inside the Linux kernel
- Just-in-Time Compilation: eBPF bytecode is compiled to native machine code for optimal performance
- Safety Verification: The kernel verifier ensures programs can't crash or compromise the system
- Maps: Efficient key-value storage for sharing data between eBPF programs and user space
- Helper Functions: Access to kernel functionality through a set of helper functions
- Attachment Points: Programs can be attached to various kernel hooks (syscalls, network, tracing, etc.)

### Common Use Cases
- Networking: XDP (eXpress Data Path) programs for high-performance packet processing
- Security: System call filtering, process monitoring, and security policy enforcement
- Observability: Tracing kernel and application behavior with minimal overhead
- Performance Analysis: Collecting metrics and analyzing system performance

### Writing eBPF Programs
eBPF programs are typically written in C and compiled to eBPF bytecode using LLVM/Clang. Higher-level frameworks like BCC (BPF Compiler Collection), libbpf, and bpftrace provide easier ways to develop and deploy eBPF programs.

### Purpose
- This repository serves as a learning resource and reference implementation for anyone studying eBPF through the "Learning eBPF" book. The modifications showcase alternative techniques and provide additional insights beyond the original text.
- Feel free to explore, use, and modify these examples for your own learning journey with eBPF.

