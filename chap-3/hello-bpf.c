
// Contains core eBPF definitions.
#include <linux/bpf.h>
//Provides helper functions like bpf_printk
#include <bpf/bpf_helpers.h>

int counter = 0;

//This macro marks the function to be attached to the XDP hook point.
SEC("xdp") 

int hello(void *ctx) {
	bpf_printk("Hello World %d", counter);
	counter++;

	return XDP_PASS;
}

//The LICENSE[] declaration with SEC("license") specifies the program's license, which is required by the kernel (in this case, it's dual-licensed under BSD and GPL)
char LICENSE[] SEC("license") = "Dual BSD/GPL";