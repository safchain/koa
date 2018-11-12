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
    int rwflag;
    char name[TASK_COMM_LEN];
};

// the value of the output summary
struct value_t
{
    __u64 bytes;
    __u32 io;
};

#endif