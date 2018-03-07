/* Netlink socket family used by a Pyronia-aware language runtime
 * to send callstack information to the Pyronia LSM for access control
 * decisions.
 *
 *@author Marcela S. Melara
 */

#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sched.h>

#include "include/callgraph.h"
#include "include/si_comm.h"

struct sock *upcall_sock = NULL;

/* family definition */
static struct genl_family si_comm_gnl_family = {
    .id = GENL_ID_GENERATE,         //genetlink should generate an id
    .hdrsize = 0,
    .name = "SI_COMM", // name of this family, used by userspace
    .version = VERSION_NR,                   //version number
    .maxattr = SI_COMM_A_MAX,
};

/* STACK_REQ command: send a message requesting the current language
 * runtime's callstack from the given process, and return the callgraph
 * to the caller. */
pyr_cg_node_t *pyr_stack_request(u32 pid)
{
    struct sk_buff *skb;
    void *msg_head;
    int rc;

    // allocate the message memory
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL) {
        printk("[%s] Could not allocate skb for STACK_REQ for %d\n",
               __func__, pid);
        return 0;
    }

    //Create the message headers
    /* arguments of genlmsg_put:
       struct sk_buff *,
       int (sending) pid,
       int sequence number,
       struct genl_family *,
       int flags,
       u8 command index (why do we need this?)
    */
    msg_head = genlmsg_put(skb, 0, 0, &si_comm_gnl_family,
                           0, SI_COMM_C_STACK_REQ);

    if (msg_head == NULL) {
        rc = -ENOMEM;
        printk("[%s] genlmsg_put() returned error for %d\n", __func__, pid);
        return 0;
    }

    // create the message
    rc = nla_put_u8(skb, SI_COMM_A_KERN_REQ, STACK_REQ_CMD);
    if (rc != 0) {
        printk("[%s] Could not create the message for %d\n", __func__, pid);
        return 0;
    }

    // finalize the message
    genlmsg_end(skb, msg_head);

    // send the message
    rc = nlmsg_unicast(upcall_sock, skb, pid);
    if (rc != 0) {
        printk("[%s] Error sending message to %d\n", __func__, pid);
        return 0;
    }

    // TODO: recv message on upcall_sock here

    return 0;
}

/* REGISTER_PROC command: receive a message with a process' PID. This
 * handler then stores this PID as part of the process' ACL to enable
 * the kernel to request callstack information from the process
 * upon sensitive system calls.
 */
int pyr_register_proc(struct sk_buff *skb,  struct genl_info *info)
{
    return 0;
}

/* SAVE_CONTEXT command: receive a message with callstack information
 * to store in the specified process' Pyronia ACL. */
int pyr_save_context(struct sk_buff *skb,  struct genl_info *info)
{
    return 0;
}

/* commands:
 *
 * - REGISTER_PROC: register a language runtime instance with the LSM.
 * - SAVE_CONTEXT: pre-emptively save
 * callstack info as part of a process' access policy.*/
static const struct genl_ops si_comm_gnl_ops[] = {
    {
        .cmd = SI_COMM_C_REGISTER_PROC,
        .flags = 0,
        .policy = si_comm_genl_policy[0],
        .doit = pyr_register_proc,
    },
    {
        .cmd = SI_COMM_C_SAVE_CONTEXT,
        .flags = 0,
        .policy = si_comm_genl_policy[0],
        .doit = pyr_save_context,
    },
};

static int __init kernel_comm_init(void)
{
    int rc;

    /*register new family*/
    rc = genl_register_family_with_ops(&si_comm_gnl_family, si_comm_gnl_ops);
    if (rc != 0){
        printk("register ops: %i\n",rc);
        goto fail;
    }

    /* initialize the upcall socket */
    struct netlink_kernel_cfg cfg = {};
    upcall_sock = netlink_kernel_create(&init_net, NETLINK_GENERIC, &cfg);
    if (!upcall_sock) {
        printk("upcall socket create\n");
        goto fail;
    }

    printk(KERN_INFO "[pyronia] Initialized SI communication channel\n");
    return 0;

fail:
    genl_unregister_family(&si_comm_gnl_family);
    printk(KERN_CRIT "[pyronia] Error occured while creating SI netlink channel\n");
    return -1;
}

static void __exit kernel_comm_exit(void)
{
    int ret;

    /*unregister the family*/
    ret = genl_unregister_family(&si_comm_gnl_family);
    if(ret !=0){
        printk("unregister family %i\n",ret);
    }

    printk(KERN_INFO "[pyronia] SI channel teardown complete\n");
}


module_init(kernel_comm_init);
module_exit(kernel_comm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcela S. Melara");
MODULE_DESCRIPTION("Main component for stack inspection-related LSM-to-userspace communication.");
