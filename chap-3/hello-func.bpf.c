// Include necessary headers for eBPF development
#include <linux/bpf.h>       // Core eBPF definitions, constants, and structures
#include <bpf/bpf_helpers.h> // Helper functions like bpf_printk, bpf_map_lookup_elem, etc.

/**
 * Helper function to extract the syscall number from tracepoint context
 * 
 * This function demonstrates a BPF-to-BPF function call capability.
 * The __attribute((noinline)) is crucial as it prevents the compiler from
 * inlining this function, allowing it to be called by other BPF functions.
 * 
 * @param ctx Pointer to the raw tracepoint arguments structure
 * @return The syscall number (opcode) from args[1]
 */
static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    // For syscall tracepoints, args[1] typically contains the syscall number
    return ctx->args[1];
}

/**
 * Main BPF program entry point that attaches to the raw tracepoint
 * 
 * The SEC("raw_tp/") macro specifies that this function should be placed in the 
 * raw_tp/ section of the ELF file. Typically you would specify a particular 
 * tracepoint like "raw_tp/sys_enter" to trace all system calls.
 * 
 * @param ctx Pointer to raw tracepoint arguments passed by the kernel
 * @return 0 (return value not used by raw tracepoints)
 */
SEC("raw_tp/")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    // Call our helper function to get the syscall number
    int opcode = get_opcode(ctx);
    
    // Print the syscall number to the kernel trace pipe
    // This can be read from /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("Syscall: %d", opcode);
    
    // Return 0 (success) - though this value is ignored for tracepoints
    return 0;
}

/**
 * License declaration for the BPF program
 * 
 * The kernel requires all BPF programs to declare a compatible license.
 * This declaration must be in a special section called "license".
 * "Dual BSD/GPL" allows this code to be used under either license.
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";