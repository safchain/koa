#ifndef __IO_H
#define __IO_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// the key for the output summary
struct key_t
{
    __u32 pid;
    int major;
    int minor;
};

// the value of the output summary
struct value_t
{
    __u64 rbytes;
    __u64 rio;
    __u64 wbytes;
    __u64 wio;
    char name[TASK_COMM_LEN];
};

#endif