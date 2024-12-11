#!/usr/bin/env python3
from bcc import BPF
import signal
import sys

# BPF program to trace brk() system call and capture stack trace
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    // no pid (thread ID) so that we do not needlessly split this key
    u32 tgid;
    int kernel_stack_id;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE(stack_traces, 1024);

int trace_brk(void *ctx) {

    struct key_t key = {};
    key.tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    key.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    key.kernel_stack_id = stack_traces.get_stackid(ctx, 0);
    counts.atomic_increment(key);
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_program)

# Attach to the brk system call entry point (system call number 45)
b.attach_tracepoint(tp="syscalls:sys_enter_brk", fn_name="trace_brk")
# b.attach_kprobe(event="sys_brk", fn_name="trace_brk")

print("Tracing brk() system calls... Press Ctrl+C to stop.")

# Define signal handler for cleanup
def exit_handler(signum, frame):
    print("\nExiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, exit_handler)

# Print the stack traces
try:
    while True:
        # Poll for new stack traces
        stack_traces = b["stack_traces"]
        for stack_id in stack_traces.values():
            stack = b.get_stack_trace(stack_id)
            print("Stack trace:")
            for addr in stack:
                print(f"  {hex(addr)}")
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting...")
    sys.exit(0)

