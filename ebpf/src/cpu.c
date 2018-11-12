#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf.h"

#include <linux/sched.h>

#include "cpu.h"

struct bpf_map_def SEC("maps/start_map") start_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/value_map") value_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct value_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

SEC("kprobe/finish_task_switch")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
    struct task_struct *prev = (void *)ctx->di;

    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;

    u32 state = 0;
    bpf_probe_read(&state, sizeof(state), (void *)&prev->state);
    if (state == TASK_RUNNING)
    {
        u32 prev_pid = 0;
        u32 prev_tgid = 0;

        bpf_probe_read(&prev_pid, sizeof(prev_pid), (void *)&prev->pid);
        bpf_probe_read(&prev_tgid, sizeof(prev_tgid), (void *)&prev->tgid);

        u64 *tsp = bpf_map_lookup_elem(&start_map, &pid);
        if (tsp == 0 || ts < *tsp)
        {
            return 0;
        }

       struct value_t zero = {};

        u64 delta = ts - *tsp;
        struct value_t *value = bpf_map_lookup_elem(&value_map, &pid);
        if (value == NULL)
        {
            bpf_get_current_comm(&zero.name, sizeof(zero.name));
            zero.ns = delta;

            bpf_map_update_elem(&value_map, &pid, &zero, BPF_ANY);
        }
        else
        {
            value->ns += delta;
        }
    }
    bpf_map_update_elem(&start_map, &pid, &ts, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0xFFFFFFFE;