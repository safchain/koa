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

#include "malloc.h"

struct bpf_map_def SEC("maps/value_map") value_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct value_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

SEC("uprobe/malloc")
int uprobe__malloc(struct pt_regs *ctx)
{
    size_t size = (size_t)ctx->di;

    u32 pid = bpf_get_current_pid_tgid();

    struct value_t zero = {};

    struct value_t *value = bpf_map_lookup_elem(&value_map, &pid);
    if (value == NULL)
    {
        zero.bytes = size;
        bpf_get_current_comm(&zero.name, sizeof(zero.name));

        bpf_map_update_elem(&value_map, &pid, &zero, BPF_ANY);
        value = &zero;
    }
    else
    {
        value->bytes += size;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0xFFFFFFFE;