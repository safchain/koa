#ifndef __CPU_H
#define __CPU_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// the value of the output summary
struct value_t
{
    __u64 ns;
    char name[TASK_COMM_LEN];
};

#endif