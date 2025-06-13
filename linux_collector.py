#!/usr/bin/env python3

from bcc import BPF
from bcc.utils import printb
import ctypes as ct
import time
import datetime
import sys
import os
import socket # For ntohs, ntohl if needed, though bcc usually handles it

# --- CSV Header ---
CSV_HEADER = "Timestamp,PID,UID,Comm,EventType,Syscall,SrcIP,DstIP,SrcPort,DstPort,Details"

# --- eBPF C Code ---
BPF_C_CODE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h> // For MAX_PATH_LEN if needed from here
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

// TASK_COMM_LEN is defined in linux/sched.h, usually 16
// MAX_COMM_LEN for our use, can be larger if needed for other metadata
#define MAX_COMM_LEN 64
#define MAX_PATH_LEN 256

// Event types
enum event_type {
    EVENT_TYPE_PROCESS_EXEC,
    EVENT_TYPE_NETWORK_CONNECT_V4,
};

// Common header for events to easily determine type
struct event_header_t {
    enum event_type type;
    u32 padding; // To ensure consistent alignment if needed, can be omitted if not strictly necessary
};

// Data structure for process execution events
struct process_event_t {
    struct event_header_t header;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN]; // Use kernel's TASK_COMM_LEN for bpf_get_current_comm
    char path[MAX_PATH_LEN];
};

// Data structure for IPv4 network connection events
struct net_event_v4_t {
    struct event_header_t header;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN]; // Use kernel's TASK_COMM_LEN
    u32 saddr; // host byte order
    u32 daddr; // host byte order
    u16 sport; // host byte order
    u16 dport; // host byte order (already converted from network in BPF)
};

// Perf output channel for events
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct process_event_t event = {};
    event.header.type = EVENT_TYPE_PROCESS_EXEC;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // args is struct trace_event_raw_sched_process_exec*
    // The filename is accessible via args->filename or a similar field.
    // This requires BTF or knowledge of the kernel struct for tracepoints.
    // bpf_probe_read_str is safer than direct pointer access for user strings.
    bpf_probe_read_str(&event.path, sizeof(event.path), (void *)args->filename);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// Kprobe for tcp_v4_connect
// The first argument to tcp_v4_connect is struct sock *sk.
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL) { // Basic null check
        return 0;
    }

    struct net_event_v4_t event = {};
    event.header.type = EVENT_TYPE_NETWORK_CONNECT_V4;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // Lower 32 bits for UID
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // sk->__sk_common fields are generally in host byte order in kernel space.
    event.daddr = sk->__sk_common.skc_daddr;
    event.saddr = sk->__sk_common.skc_rcv_saddr; // Use rcv_saddr for established source

    // skc_dport is network byte order, convert to host for consistency.
    event.dport = bpf_ntohs(sk->__sk_common.skc_dport);

    // inet_sport is already host byte order in struct inet_sock.
    struct inet_sock *inet = inet_sk(sk);
    if (inet != NULL) {
        event.sport = inet->inet_sport;
    } else {
        event.sport = 0; // Placeholder if inet_sock isn't accessible
    }

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# --- Python Event Processing ---

class EventType(object):
    PROCESS_EXEC = 0
    NETWORK_CONNECT_V4 = 1

class EventHeader(ct.Structure):
    _fields_ = [
        ("type", ct.c_int),
        ("padding", ct.c_uint)
    ]

class ProcessEvent(ct.Structure):
    _fields_ = [
        ("header", EventHeader),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("comm", ct.c_char * 16), # TASK_COMM_LEN
        ("path", ct.c_char * 256), # MAX_PATH_LEN
    ]

class NetEventV4(ct.Structure):
    _fields_ = [
        ("header", EventHeader),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("comm", ct.c_char * 16), # TASK_COMM_LEN
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
    ]

def int_to_ip(addr_int):
    # Converts a host byte order 32-bit integer to an IPv4 string.
    try:
        # socket.inet_ntoa expects a 4-byte string in network byte order.
        # Convert host order addr_int to network order bytes.
        return socket.inet_ntoa(addr_int.to_bytes(4, byteorder='big'))
    except Exception:
        return ""


def print_event_callback(cpu, data, size):
    header = ct.cast(data, ct.POINTER(EventHeader)).contents
    timestamp = datetime.datetime.now().isoformat()

    if header.type == EventType.PROCESS_EXEC:
        if size < ct.sizeof(ProcessEvent): return # Malformed
        event = ct.cast(data, ct.POINTER(ProcessEvent)).contents
        path_str = event.path.decode('utf-8', 'replace').strip()
        comm_str = event.comm.decode('utf-8', 'replace').strip()
        # CSV: Timestamp,PID,UID,Comm,EventType,Syscall,SrcIP,DstIP,SrcPort,DstPort,Details
        csv_line = f"{timestamp},{event.pid},{event.uid},{comm_str},process_exec,execve,,,,\"{path_str}\""
        print(csv_line)

    elif header.type == EventType.NETWORK_CONNECT_V4:
        if size < ct.sizeof(NetEventV4): return # Malformed
        event = ct.cast(data, ct.POINTER(NetEventV4)).contents
        # IPs from BPF are host order, convert to string.
        saddr_str = int_to_ip(event.saddr)
        daddr_str = int_to_ip(event.daddr)
        comm_str = event.comm.decode('utf-8', 'replace').strip()

        # Ports from BPF are host order.
        sport_str = str(event.sport) if event.sport != 0 else ""
        dport_str = str(event.dport) if event.dport != 0 else ""

        # CSV: Timestamp,PID,UID,Comm,EventType,Syscall,SrcIP,DstIP,SrcPort,DstPort,Details
        csv_line = f"{timestamp},{event.pid},{event.uid},{comm_str},network_connect,connect,{saddr_str},{daddr_str},{sport_str},{dport_str}," # No details for connect
        print(csv_line)
    else:
        # print(f"Unknown event type: {header.type}", file=sys.stderr)
        pass

    sys.stdout.flush()


def main():
    if os.geteuid() != 0:
        print("This script must be run as root to attach eBPF programs.", file=sys.stderr)
        sys.exit(1)

    try:
        b = BPF(text=BPF_C_CODE)
    except Exception as e:
        print(f"Error initializing BPF: {e}", file=sys.stderr)
        print("Please ensure that you have kernel headers installed (e.g., linux-headers-$(uname -r)) "
              "and that the bcc tools (python3-bcc) are correctly installed and configured.", file=sys.stderr)
        sys.exit(1)

    print(CSV_HEADER) # Print header once
    sys.stdout.flush()

    # lost_cb is a callback for when events are lost from the perf buffer
    def lost_events_callback(lost_count):
        print(f"Kernel lost {lost_count} events.", file=sys.stderr)
        sys.stderr.flush()

    b["events"].open_perf_buffer(print_event_callback, page_cnt=256, lost_cb=lost_events_callback)

    print("Monitoring process executions and network connections... Press Ctrl+C to stop.", file=sys.stderr)
    sys.stderr.flush()

    try:
        while True:
            b.perf_buffer_poll(timeout=200) # Poll perf buffer with a timeout
    except KeyboardInterrupt:
        print("\nStopping monitoring gracefully...", file=sys.stderr)
    except Exception as e:
        # Catch other potential errors during polling
        print(f"An error occurred during monitoring: {e}", file=sys.stderr)
    finally:
        print("Exiting.", file=sys.stderr)
        # b.cleanup() # Optional: bcc usually handles cleanup on exit
        sys.exit(0)

if __name__ == "__main__":
    try:
        from bcc import BPF # Check for bcc import early
    except ImportError:
        print("ImportError: bcc library not found. Please install bcc-tools (e.g., python3-bcc).", file=sys.stderr)
        sys.exit(1)
    main()
