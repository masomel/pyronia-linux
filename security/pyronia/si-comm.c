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

/* attributes (variables): the index in this enum is used as a reference
 * for the type, userspace application has to indicate the corresponding
 * type the policy is used for security considerations
 */

enum {
        SI_COMM_A_UNSPEC,
        SI_COMM_A_MSG,
    __SI_COMM_A_MAX,
};
#define SI_COMM_A_MAX (__SI_COMM_A_MAX - 1)

/* attribute policy: defines which attribute has which type (e.g int,
 * char * etc) possible values defined in net/netlink.h
 */
static struct nla_policy si_comm_genl_policy[SI_COMM_A_MAX + 1] = {
    // TODO: is this the message format we want?
    [SI_COMM_A_MSG] = { .type = NLA_NUL_STRING },
};

#define VERSION_NR 1
/* family definition */
static struct genl_family si_comm_gnl_family = {
    .id = GENL_ID_GENERATE,         //genetlink should generate an id
    .hdrsize = 0,
    .name = "SI_COMM", // name of this family, used by userspace
    .version = VERSION_NR,                   //version number
    .maxattr = SI_COMM_A_MAX,
};

/* commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be ececuted
 */
enum {
        SI_COMM_C_UNSPEC,
        SI_COMM_C_STACK_REQ,
        SI_COMM_C_REGISTER_STACK,
        __SI_COMM_C_MAX,
};
#define SI_COMM_C_MAX (__SI_COMM_C_MAX - 1)

/* STACK_REQ command: send a message requesting the current language
 * runtime's callstack. */
int si_stack_request(struct sk_buff *skb_2,  struct genl_info *info)
{
    return 0;
}

/* REGISTER_STACK command: receive a message with callstack information
 * to store in the specified process' Pyronia ACL. */
int si_register_stack(struct sk_buff *skb_2,  struct genl_info *info)
{
    return 0;
}

/* commands:
 *
 * - STACK_REQ: the kernel upcall to request a callstack
 * for an access control decisions upon a syscall interception.
 * - REGISTER_STACK: the userspace downcall to pre-emptively register
 * callstack info as part of a process' access policy.*/
static const struct genl_ops si_comm_gnl_ops[] = {
    {
        .cmd = SI_COMM_C_STACK_REQ,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = si_stack_request,
    },
    {
        .cmd = SI_COMM_C_REGISTER_STACK,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = si_register_stack,
    },
};

static int __init kernel_comm_init(void)
{
    int rc;

    /*register new family*/
    rc = genl_register_family_with_ops(&si_comm_gnl_family, si_comm_gnl_ops);
    if (rc != 0){
        printk("register ops: %i\n",rc);
        genl_unregister_family(&si_comm_gnl_family);
        goto failure;
    }

    printk(KERN_INFO "[pyronia] Initialized SI communication channel\n");
    return 0;

failure:
    printk(KERN_CRIT "[pyronia] error occured while inserting the netlink module\n");
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
