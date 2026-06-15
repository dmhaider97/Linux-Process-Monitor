from bcc import BPF
import os
import logging

LOG_FILE = "process_monitor.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING, # Only log warnings and above
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# C Code
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_PATH_LEN 128

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename, const char __user *const *argv, const char __user *const *envp) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Defining the watchlist
WATCHED_BINS = {"nc", "nmap", "curl", "wget", "socat", "netcat", "nc.traditional", "nc.openbsd", "ncat"}
WATCHED_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")

def evaluate_threat(pid, uid, target_bin, filepath):
    alerts = []

    if filepath.startswith(WATCHED_DIRS):
        alerts.append("EXEC FROM TEMP DIR")

    if target_bin in WATCHED_BINS:
        alerts.append(f"SUSPICIOUS BINARY ({target_bin})")

    if uid == 0 and target_bin in {"curl", "wget", "nc", "nc.traditional", "nc.openbsd", "ncat"}:
        alerts.append("ROOT NETWORK TOOL EXEC")

    return alerts
"""
\



00000000000000000000000000000000000000054
"""
# ^^My cat Jasper stepped on my keyboard, leaving it as an Easter egg

# Defining the callback to process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    
    caller_comm = event.comm.decode('utf-8', 'replace').strip('\x00')
    filepath = event.filename.decode('utf-8', 'replace').strip('\x00')
    target_bin = os.path.basename(filepath)
    
    threat_flags = evaluate_threat(event.pid, event.uid, target_bin, filepath)
    
    if threat_flags:
        flags_str = " | ".join(threat_flags)
        
        # Compiling the alert
        alert_msg = f"{flags_str} -> PID: {event.pid} | UID: {event.uid} | TARGET: {target_bin} | CALLER: {caller_comm}"
        
        # Writing to the log file
        logging.warning(alert_msg)
        
        # Printing to the terminal
        print(f"[ALERT] {flags_str}")
        print(f" -> PID: {event.pid} | UID: {event.uid} | TARGET: {target_bin} | CALLER: {caller_comm}")
        print("-" * 50)

# Initializing BPF and attaching to kernel
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

print(f"Writing alerts to: {os.path.abspath(LOG_FILE)}")
print("Filtering for suspicious activity. Press Ctrl+C to stop...\n")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nExiting...")