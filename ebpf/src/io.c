#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf.h"

#include <linux/blkdev.h>

#include "io.h"

struct process_t
{
	u32 pid;
	char name[TASK_COMM_LEN];
};

struct bpf_map_def SEC("maps/process_map") process_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct request *),
	.value_size = sizeof(struct process_t),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/start_map") start_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct request *),
	.value_size = sizeof(u64),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

struct bpf_map_def SEC("maps/value_map") value_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct key_t),
	.value_size = sizeof(struct value_t),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

SEC("kprobe/blk_account_io_start")
int kprobe__blk_account_io_start(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM1(ctx);

	struct process_t process = {};
	if (bpf_get_current_comm(&process.name, sizeof(process.name)) == 0)
	{
		process.pid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&process_map, &req, &process, BPF_ANY);
	}
	return 0;
}

__attribute__((always_inline)) static inline int trace_req_start(struct pt_regs *ctx)
{
	struct request *req = (struct request *)PT_REGS_PARM1(ctx);

	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_map, &req, &ts, BPF_ANY);
	return 0;
}

SEC("kprobe/blk_start_request")
int kprobe__blk_start_request(struct pt_regs *ctx)
{
	return trace_req_start(ctx);
}

SEC("kprobe/blk_mq_start_request")
int kprobe__blk_mq_start_request(struct pt_regs *ctx)
{
	return trace_req_start(ctx);
}

SEC("kprobe/blk_account_io_completion")
int kprobe__blk_account_io_completion(struct pt_regs *ctx)
{
	struct request *req = (void *)ctx->di;

	u64 *tsp = bpf_map_lookup_elem(&start_map, &req);
	if (tsp == NULL)
	{
		return 0;
	}

	struct key_t key = {};

	u32 len = 0;
	bpf_probe_read(&len, sizeof(len), &req->__data_len);

	struct gendisk *gendisk = NULL;
	bpf_probe_read(&gendisk, sizeof(gendisk), (void *)&req->rq_disk);

	bpf_probe_read(&key.major, sizeof(key.major), (void *)&(gendisk->major));
	bpf_probe_read(&key.minor, sizeof(key.minor), (void *)&(gendisk->first_minor));

	u32 rwflag = 0;
	bpf_probe_read(&rwflag, sizeof(rwflag), &req->cmd_flags);

#ifdef REQ_WRITE
	key.rwflag = !!(rwflag & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
	key.rwflag = !!((rwflag >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
	key.rwflag = !!((rwflag & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

	struct process_t *process = bpf_map_lookup_elem(&process_map, &req);
	if (process != NULL)
	{
		key.pid = process->pid;
		__builtin_memcpy(&key.name, process->name, sizeof(key.name));
	}

	struct value_t *value, zero = {};

	value = bpf_map_lookup_elem(&value_map, &key);
	if (value == NULL)
	{
		bpf_map_update_elem(&value_map, &key, &zero, BPF_ANY);
		value = &zero;
	}
	value->bytes += len;
	value->io++;

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 0xFFFFFFFE;