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

#include "vfs.h"

struct bpf_map_def SEC("maps/value_map") value_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct value_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

static inline __attribute__((always_inline)) struct value_t *get_value(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct value_t zero = {};

    struct value_t *value = bpf_map_lookup_elem(&value_map, &pid);
    if (value == NULL)
    {
        bpf_get_current_comm(&zero.name, sizeof(zero.name));
        bpf_map_update_elem(&value_map, &pid, &zero, BPF_ANY);
        value = &zero;
    }

    return value;
}

SEC("kprobe/vfs_read")
int kprobe__vfs_read(struct pt_regs *ctx)
{
    struct value_t *value = get_value(ctx);
    if (value == NULL)
    {
        return 0;
    }
    value->read++;

    return 0;
}

SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx)
{
    struct value_t *value = get_value(ctx);
    if (value == NULL)
    {
        return 0;
    }
    value->write++;

    return 0;
}

SEC("kprobe/vfs_open")
int kprobe__vfs_open(struct pt_regs *ctx)
{
    struct value_t *value = get_value(ctx);
    if (value == NULL)
    {
        return 0;
    }
    value->open++;

    return 0;
}

SEC("kprobe/vfs_create")
int kprobe__vfs_create(struct pt_regs *ctx)
{
    struct value_t *value = get_value(ctx);
    if (value == NULL)
    {
        return 0;
    }
    value->create++;

    return 0;
}

SEC("kprobe/vfs_fsync")
int kprobe__vfs_fsync(struct pt_regs *ctx)
{
    struct value_t *value = get_value(ctx);
    if (value == NULL)
    {
        return 0;
    }
    value->fsync++;

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0xFFFFFFFE;