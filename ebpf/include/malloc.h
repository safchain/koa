#ifndef __MALLOC_H
#define __MALLOC_H

#include <linux/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// the value of the output summary
struct value_t
{
    __u64 bytes;
    char name[TASK_COMM_LEN];
};

#endif