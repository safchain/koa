#ifndef __FUNCLAT_H
#define __FUNCLAT_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// the key for the output summary
struct key_t
{
    __u32 pid;
    __u64 ip;
};

// the value of the output summary
struct value_t
{
    __u64 calls;
    __u64 ns;
    char name[TASK_COMM_LEN];
};

#endif