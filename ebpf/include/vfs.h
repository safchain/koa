#ifndef __CPU_H
#define __CPU_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// the value of the output summary
struct value_t
{
    __u64 read;
    __u64 write;
    __u64 open;
    __u64 create;
    __u64 fsync;
    char name[TASK_COMM_LEN];
};

#endif