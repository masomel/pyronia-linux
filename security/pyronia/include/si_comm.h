/* Defines the Netlink socket family used by a Pyronia-aware language runtime
 * to send callstack information to the Pyronia LSM for access control
 * decisions.
 *
 *@author Marcela S. Melara
 */

#ifndef __PYR_SI_COMM_H
#define __PYR_SI_COMM_H

#include "callgraph.h"

#define STACK_REQ_CMD 0
#define VERSION_NR 1

/* attributes (variables): the index in this enum is used as a reference
 * for the type, userspace application has to indicate the corresponding
 * type the policy is used for security considerations
 */

enum {
        SI_COMM_A_UNSPEC,
        SI_COMM_A_USR_MSG,
        SI_COMM_A_KERN_REQ,
    __SI_COMM_A_MAX,
};
#define SI_COMM_A_MAX (__SI_COMM_A_MAX - 1)

/* commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be ececuted
 */
enum {
        SI_COMM_C_UNSPEC,
        SI_COMM_C_REGISTER_PROC,
        SI_COMM_C_SAVE_CONTEXT,
        SI_COMM_C_STACK_REQ,
        __SI_COMM_C_MAX,
};
#define SI_COMM_C_MAX (__SI_COMM_C_MAX - 1)

pyr_cg_node_t *pyr_stack_request(u32);
int pyr_register_proc(struct sk_buff *,  struct genl_info *);
int pyr_save_context(struct sk_buff *,  struct genl_info *);

#endif /* __PYR_SI_COMM_H */
