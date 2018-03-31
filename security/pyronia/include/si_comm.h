#ifndef __PYR_SI_COMM_H
#define __PYR_SI_COMM_H

#include <linux/mutex.h>
#include <uapi/linux/pyronia_mac.h>

extern struct mutex pyr_si_mutex;

pyr_cg_node_t *pyr_stack_request(u32 pid);

#endif
