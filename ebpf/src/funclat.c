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

#include "funclat.h"

struct bpf_map_def SEC("maps/value_map") value_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct key_t),
    .value_size = sizeof(struct value_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

SEC("uprobe/entry")
int uprobe__entry(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ip = PT_REGS_IP(ctx);

    struct key_t key = {};
    key.pid = pid;
    key.ip = ip;

    struct value_t zero = {};

    struct value_t *value = bpf_map_lookup_elem(&value_map, &key);
    if (value == NULL)
    {
        bpf_get_current_comm(&zero.name, sizeof(zero.name));
        bpf_map_update_elem(&value_map, &key, &zero, BPF_ANY);
        value = &zero;
    }
    value->calls++;

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0xFFFFFFFE;